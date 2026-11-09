// Package cniplugin implements the zora CNI plugin: a chained plugin that
// runs after the cluster's primary CNI and, for pods that ask for one, adds
// a WireGuard interface.
//
// Being a guest in someone else's CNI chain shapes every decision here:
//
//   - ADD passes the primary's result through untouched for pods without a
//     WireGuard config, adding only an interface entry for pods with one.
//     It never adds IPs, so the runtime keeps choosing the pod IP from the
//     primary interface.
//   - ADD fails closed: if the agent is unreachable, a pod that may want a
//     tunnel does not start without one. Namespaces in excludeNamespaces
//     (kube-system by default) never consult the agent, so cluster
//     infrastructure keeps working while zora is broken.
//   - DEL never fails. Failing DEL wedges pod deletion; everything zora
//     creates in the pod dies with its namespace anyway, and host-side
//     leftovers have deterministic names that DEL and GC clean up without
//     the agent.
//
// All kernel work goes through the Netlink interface and all agent calls
// through Agent, so this package is unit-tested with fakes; the real binary
// is tested end to end in test/integration.
package cniplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/netapply"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

// SupportedVersions are the CNI spec versions zora speaks.
var SupportedVersions = version.PluginSupports("0.4.0", "1.0.0", "1.1.0")

// DefaultExcludeNamespaces applies when the config has no
// excludeNamespaces key. An explicit empty list excludes nothing.
var DefaultExcludeNamespaces = []string{"kube-system"}

// PodAnnotationsCapability is the runtimeConfig key under which containerd
// passes pod annotations to plugins that declare the capability.
const PodAnnotationsCapability = "io.kubernetes.cri.pod-annotations"

// NetConf is zora's entry in the conflist.
type NetConf struct {
	types.PluginConf
	// Socket is the agent's socket. Default agentapi.DefaultSocket.
	Socket string `json:"socket,omitempty"`
	// ExcludeNamespaces never consult the agent. Default
	// DefaultExcludeNamespaces.
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
	// TimeoutSeconds bounds each agent call. Default
	// agentapi.DefaultTimeout.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	RuntimeConfig *struct {
		PodAnnotations map[string]string `json:"io.kubernetes.cri.pod-annotations,omitempty"`
	} `json:"runtimeConfig,omitempty"`
}

// Agent is the part of the agent API the plugin uses.
type Agent interface {
	Resolve(ctx context.Context, req agentapi.ResolveRequest) (*agentapi.ResolveResponse, error)
	Report(ctx context.Context, req agentapi.ReportRequest) error
	Healthy(ctx context.Context) error
}

// Netlink is the kernel work the plugin does.
type Netlink interface {
	Apply(podNS string, p *plan.Plan, opts netapply.Options) error
	Remove(podNS string, p *plan.Plan, opts netapply.Options) error
	Verify(podNS string, p *plan.Plan) error
	UplinkMTU(podNS, ifName string) (int, error)
	DeleteHostOrphans(opts netapply.Options, keep func(string) bool) ([]string, error)
}

// Plugin is the CNI plugin. The zero value is not usable; see New.
type Plugin struct {
	NewAgent func(socket string, timeout time.Duration) Agent
	Net      Netlink
	// Log receives diagnostics. The runtime usually captures stderr.
	Log io.Writer
}

// Funcs adapts the plugin to skel.
func (p *Plugin) Funcs() skel.CNIFuncs {
	return skel.CNIFuncs{
		Add: func(args *skel.CmdArgs) error {
			conf, result, err := p.Add(args)
			if err != nil {
				return err
			}
			return types.PrintResult(result, conf.CNIVersion)
		},
		Del:    p.Del,
		Check:  p.Check,
		GC:     p.GC,
		Status: p.Status,
	}
}

func (p *Plugin) logf(format string, args ...any) {
	if p.Log != nil {
		_, _ = fmt.Fprintf(p.Log, "zora: "+format+"\n", args...)
	}
}

// ParseConf parses and validates the plugin's stdin config.
func ParseConf(stdin []byte) (*NetConf, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := version.ParsePrevResult(&conf.PluginConf); err != nil {
		return nil, err
	}
	if conf.Socket == "" {
		conf.Socket = agentapi.DefaultSocket
	}
	if conf.ExcludeNamespaces == nil {
		conf.ExcludeNamespaces = DefaultExcludeNamespaces
	}
	if conf.TimeoutSeconds < 0 {
		return nil, errors.New("timeoutSeconds must not be negative")
	}
	return conf, nil
}

func (c *NetConf) timeout() time.Duration {
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	return agentapi.DefaultTimeout
}

// podFromArgs extracts the pod from CNI_ARGS ("K=V;K=V"). ok is false for
// sandboxes that are not Kubernetes pods.
func podFromArgs(cniArgs string) (agentapi.Pod, bool) {
	var pod agentapi.Pod
	for kv := range strings.SplitSeq(cniArgs, ";") {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "K8S_POD_NAMESPACE":
			pod.Namespace = v
		case "K8S_POD_NAME":
			pod.Name = v
		case "K8S_POD_UID":
			pod.UID = v
		}
	}
	return pod, pod.Namespace != "" && pod.Name != ""
}

// errAgent wraps agent failures as CNI errors with an actionable message.
func errAgent(socket string, err error) error {
	var unavailable *agentapi.UnavailableError
	if errors.As(err, &unavailable) {
		return types.NewError(types.ErrTryAgainLater,
			fmt.Sprintf("zora agent unreachable at %s; pods outside excludeNamespaces cannot start on this node until zora-agent is running", socket),
			err.Error())
	}
	return types.NewError(types.ErrInternal, err.Error(), "")
}

// Add handles CNI ADD. It returns the result to print in conf.CNIVersion.
func (p *Plugin) Add(args *skel.CmdArgs) (*NetConf, types.Result, error) {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		return nil, nil, err
	}
	if conf.PrevResult == nil {
		return nil, nil, types.NewError(types.ErrInvalidNetworkConfig,
			"zora must be chained after a primary CNI plugin, but it received no prevResult", "")
	}
	pod, isPod := podFromArgs(args.Args)
	if !isPod || slices.Contains(conf.ExcludeNamespaces, pod.Namespace) {
		return conf, conf.PrevResult, nil
	}
	if rc := conf.RuntimeConfig; rc != nil && rc.PodAnnotations != nil && rc.PodAnnotations[agentapi.AnnotationSecret] == "" {
		// The runtime told us the annotations, and the pod didn't opt in.
		return conf, conf.PrevResult, nil
	}

	mtu, err := p.Net.UplinkMTU(args.Netns, args.IfName)
	if err != nil {
		p.logf("reading %s MTU: %v (the plan will use a default)", args.IfName, err)
	}
	agent := p.NewAgent(conf.Socket, conf.timeout())
	ctx, cancel := context.WithTimeout(context.Background(), conf.timeout())
	defer cancel()
	resp, err := agent.Resolve(ctx, agentapi.ResolveRequest{Pod: pod, ContainerID: args.ContainerID, UplinkMTU: mtu})
	if err != nil {
		return nil, nil, errAgent(conf.Socket, err)
	}
	if resp.Action == agentapi.ActionSkip {
		return conf, conf.PrevResult, nil
	}

	pl, err := resp.Plan.Decode()
	if err == nil && pl.Link.Name == args.IfName {
		err = fmt.Errorf("agent asked for interface %s, which is the primary interface", pl.Link.Name)
	}
	if err == nil {
		err = p.Net.Apply(args.Netns, pl, netapply.Options{})
	}
	report := agentapi.ReportRequest{Pod: pod, ContainerID: args.ContainerID, OK: err == nil}
	if pl != nil {
		report.Warnings = pl.Warnings
	}
	if err != nil {
		report.Error = err.Error()
	}
	// Best effort: the agent uses reports for Events and readiness, but
	// the pod's networking does not depend on it hearing back.
	if rerr := agent.Report(ctx, report); rerr != nil {
		p.logf("reporting to agent: %v", rerr)
	}
	if err != nil {
		return nil, nil, types.NewError(types.ErrInternal, "setting up WireGuard: "+err.Error(), "")
	}

	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, nil, err
	}
	result.Interfaces = append(result.Interfaces, &current.Interface{Name: pl.Link.Name, Sandbox: args.Netns})
	return conf, result, nil
}

// Del handles CNI DEL. It never fails; see the package documentation.
func (p *Plugin) Del(args *skel.CmdArgs) error {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		p.logf("DEL: %v; cleaning up with defaults", err)
	}
	// Candidate link names: interfaces the runtime says we added (from the
	// cached result), plus the default. Remove only ever deletes WireGuard
	// links, so a wrong guess is harmless.
	names := []string{plan.DefaultIfName}
	if conf != nil && conf.PrevResult != nil {
		if res, err := current.NewResultFromResult(conf.PrevResult); err == nil {
			for _, iface := range res.Interfaces {
				if iface.Sandbox != "" && iface.Name != args.IfName && !slices.Contains(names, iface.Name) {
					names = append(names, iface.Name)
				}
			}
		}
	}
	for _, name := range names {
		// ModeHost also removes a host-side link a failed ADD may have left.
		rm := &plan.Plan{Mode: plan.ModeHost, Link: plan.Link{Name: name, BirthName: plan.BirthName(args.ContainerID)}}
		if err := p.Net.Remove(args.Netns, rm, netapply.Options{}); err != nil {
			p.logf("DEL %s in %q: %v (ignored)", name, args.Netns, err)
		}
	}
	return nil
}

// Check handles CNI CHECK: the pod's WireGuard state must match what the
// agent would configure now.
func (p *Plugin) Check(args *skel.CmdArgs) error {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		return err
	}
	pod, isPod := podFromArgs(args.Args)
	if !isPod || slices.Contains(conf.ExcludeNamespaces, pod.Namespace) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), conf.timeout())
	defer cancel()
	resp, err := p.NewAgent(conf.Socket, conf.timeout()).Resolve(ctx, agentapi.ResolveRequest{Pod: pod, ContainerID: args.ContainerID})
	if err != nil {
		return errAgent(conf.Socket, err)
	}
	if resp.Action == agentapi.ActionSkip {
		return nil
	}
	pl, err := resp.Plan.Decode()
	if err != nil {
		return err
	}
	if err := p.Net.Verify(args.Netns, pl); err != nil {
		return types.NewError(types.ErrInternal, "WireGuard state differs from its config", err.Error())
	}
	return nil
}

// GC handles CNI GC: delete host-side links left by ADDs of containers that
// are no longer valid attachments.
func (p *Plugin) GC(args *skel.CmdArgs) error {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, a := range conf.ValidAttachments {
		keep[plan.BirthName(a.ContainerID)] = true
	}
	deleted, err := p.Net.DeleteHostOrphans(netapply.Options{}, func(name string) bool { return keep[name] })
	for _, name := range deleted {
		p.logf("GC: deleted orphaned host-side link %s", name)
	}
	return err
}

// Status handles CNI STATUS: zora can serve ADD only when its agent is up.
func (p *Plugin) Status(args *skel.CmdArgs) error {
	conf, err := ParseConf(args.StdinData)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), conf.timeout())
	defer cancel()
	if err := p.NewAgent(conf.Socket, conf.timeout()).Healthy(ctx); err != nil {
		return types.NewError(types.ErrPluginNotAvailable, "zora agent is not ready", err.Error())
	}
	return nil
}
