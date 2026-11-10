package cniplugin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"

	"github.com/tyler-lloyd/zora/internal/plantest"
	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/netapply"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

var versions = []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"}

const (
	testNetns       = "/var/run/netns/cni-1234"
	testContainerID = "f00dfeed"
	podArgs         = "IgnoreUnknown=1;K8S_POD_NAMESPACE=apps;K8S_POD_NAME=vpn-client;K8S_POD_INFRA_CONTAINER_ID=f00dfeed;K8S_POD_UID=uid-1"
)

// prevResult is what a primary plugin (bridge + host-local, say) returns.
func prevResult(ver string) map[string]any {
	ip := map[string]any{"address": "10.244.0.5/24", "gateway": "10.244.0.1", "interface": 1}
	if strings.HasPrefix(ver, "0.") {
		ip["version"] = "4" // pre-1.0 results carry the IP version
	}
	return map[string]any{
		"cniVersion": ver,
		"interfaces": []any{
			map[string]any{"name": "cni0", "mac": "0a:58:0a:f4:00:01"},
			map[string]any{"name": "eth0", "mac": "0a:58:0a:f4:00:05", "sandbox": testNetns},
		},
		"ips":    []any{ip},
		"routes": []any{map[string]any{"dst": "0.0.0.0/0"}},
		"dns":    map[string]any{"nameservers": []any{"10.96.0.10"}},
	}
}

func stdin(t *testing.T, ver string, extra map[string]any) []byte {
	t.Helper()
	c := map[string]any{"cniVersion": ver, "name": "k8s-pod-network", "type": "zora", "prevResult": prevResult(ver)}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cmdArgs(data []byte, cniArgs string) *skel.CmdArgs {
	return &skel.CmdArgs{ContainerID: testContainerID, Netns: testNetns, IfName: "eth0", Args: cniArgs, StdinData: data}
}

type fakeAgent struct {
	resolve   func(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error)
	healthErr error
	resolves  []agentapi.ResolveRequest
	reports   []agentapi.ReportRequest
	socket    string
	timeout   time.Duration
}

func (f *fakeAgent) Resolve(_ context.Context, r agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
	f.resolves = append(f.resolves, r)
	if f.resolve == nil {
		return nil, errors.New("Resolve called unexpectedly")
	}
	return f.resolve(r)
}

func (f *fakeAgent) Report(_ context.Context, r agentapi.ReportRequest) error {
	f.reports = append(f.reports, r)
	return nil
}

func (f *fakeAgent) Healthy(context.Context) error { return f.healthErr }

type applyCall struct {
	netns string
	plan  *plan.Plan
}

type fakeNet struct {
	applyErr, removeErr, verifyErr error
	mtu                            int
	applied, verified              []applyCall
	removed                        []applyCall
	hostLinks                      []string
	deleted                        []string
}

func (f *fakeNet) Apply(ns string, p *plan.Plan, _ netapply.Options) error {
	f.applied = append(f.applied, applyCall{ns, p})
	return f.applyErr
}

func (f *fakeNet) Remove(ns string, p *plan.Plan, _ netapply.Options) error {
	f.removed = append(f.removed, applyCall{ns, p})
	return f.removeErr
}

func (f *fakeNet) Verify(ns string, p *plan.Plan) error {
	f.verified = append(f.verified, applyCall{ns, p})
	return f.verifyErr
}

func (f *fakeNet) UplinkMTU(string, string) (int, error) {
	if f.mtu == 0 {
		return 0, errors.New("no such link")
	}
	return f.mtu, nil
}

func (f *fakeNet) DeleteHostOrphans(_ netapply.Options, keep func(string) bool) ([]string, error) {
	for _, l := range f.hostLinks {
		if !keep(l) {
			f.deleted = append(f.deleted, l)
		}
	}
	return f.deleted, nil
}

func newPlugin(a *fakeAgent, n *fakeNet) *Plugin {
	return &Plugin{
		NewAgent: func(socket string, timeout time.Duration) Agent {
			a.socket, a.timeout = socket, timeout
			return a
		},
		Net: n,
	}
}

// printed renders a result the way the runtime would read it.
func printed(t *testing.T, r types.Result, ver string) map[string]any {
	t.Helper()
	conv, err := r.GetAsVersion(ver)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(conv)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func goldenPlan(t *testing.T) *plan.Plan {
	t.Helper()
	for _, c := range plantest.Cases(t) {
		if c.Name == "pod-full-tunnel-dualstack" {
			return c.Plan
		}
	}
	t.Fatal("golden case pod-full-tunnel-dualstack not found")
	return nil
}

func configure(p *plan.Plan) func(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
	return func(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
		return &agentapi.ResolveResponse{Action: agentapi.ActionConfigure, Plan: agentapi.EncodePlan(p)}, nil
	}
}

func skip(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
	return &agentapi.ResolveResponse{Action: agentapi.ActionSkip}, nil
}

// TestAddPassesThrough covers every way a pod ends up untouched. The
// primary's result must come back unchanged and nothing may be applied.
func TestAddPassesThrough(t *testing.T) {
	cases := []struct {
		name       string
		extra      map[string]any
		cniArgs    string
		agentCalls int
	}{
		{"not a kubernetes pod", nil, "IgnoreUnknown=1", 0},
		{"default excluded namespace", nil, strings.Replace(podArgs, "=apps", "=kube-system", 1), 0},
		{"configured excluded namespace", map[string]any{"excludeNamespaces": []string{"apps"}}, podArgs, 0},
		{"runtime says not annotated", map[string]any{"runtimeConfig": map[string]any{
			PodAnnotationsCapability: map[string]string{"team": "a"}}}, podArgs, 0},
		{"agent says skip", nil, podArgs, 1},
	}
	for _, ver := range versions {
		for _, c := range cases {
			t.Run(ver+"/"+c.name, func(t *testing.T) {
				a, n := &fakeAgent{resolve: skip}, &fakeNet{}
				data := stdin(t, ver, c.extra)
				conf, res, err := newPlugin(a, n).Add(cmdArgs(data, c.cniArgs))
				if err != nil {
					t.Fatal(err)
				}
				want, _ := ParseConf(data)
				if !reflect.DeepEqual(printed(t, res, conf.CNIVersion), printed(t, want.PrevResult, ver)) {
					t.Fatalf("result changed:\n got %v\nwant %v", printed(t, res, ver), printed(t, want.PrevResult, ver))
				}
				if len(a.resolves) != c.agentCalls || len(n.applied) != 0 {
					t.Fatalf("agent calls %d (want %d), applies %d (want 0)", len(a.resolves), c.agentCalls, len(n.applied))
				}
			})
		}
	}
}

func TestAddConfigures(t *testing.T) {
	gp := goldenPlan(t)
	for _, ver := range versions {
		t.Run(ver, func(t *testing.T) {
			a, n := &fakeAgent{resolve: configure(gp)}, &fakeNet{mtu: 1450}
			// Annotations present: the fast path must not skip the agent.
			data := stdin(t, ver, map[string]any{
				"socket":         "/run/test/zora.sock",
				"timeoutSeconds": 3,
				"runtimeConfig":  map[string]any{PodAnnotationsCapability: map[string]string{agentapi.AnnotationSecret: "vpn"}},
			})
			conf, res, err := newPlugin(a, n).Add(cmdArgs(data, podArgs))
			if err != nil {
				t.Fatal(err)
			}
			if a.socket != "/run/test/zora.sock" || a.timeout != 3*time.Second {
				t.Errorf("agent client: socket %q timeout %s", a.socket, a.timeout)
			}
			wantReq := agentapi.ResolveRequest{
				Pod:         agentapi.Pod{Namespace: "apps", Name: "vpn-client", UID: "uid-1"},
				ContainerID: testContainerID, UplinkMTU: 1450,
			}
			if !reflect.DeepEqual(a.resolves, []agentapi.ResolveRequest{wantReq}) {
				t.Errorf("resolve requests = %+v", a.resolves)
			}
			if len(n.applied) != 1 || n.applied[0].netns != testNetns || !reflect.DeepEqual(n.applied[0].plan, gp) {
				t.Fatalf("applied = %+v", n.applied)
			}
			if len(a.reports) != 1 || !a.reports[0].OK || !slices.Equal(a.reports[0].Warnings, gp.Warnings) {
				t.Errorf("reports = %+v", a.reports)
			}

			out := printed(t, res, conf.CNIVersion)
			if out["cniVersion"] != ver {
				t.Errorf("result cniVersion = %v, want %s", out["cniVersion"], ver)
			}
			ifaces := out["interfaces"].([]any)
			last := ifaces[len(ifaces)-1].(map[string]any)
			if len(ifaces) != 3 || last["name"] != "wg0" || last["sandbox"] != testNetns {
				t.Errorf("interfaces = %v; want the primary's two plus wg0 in the sandbox", ifaces)
			}
			// IPs must be untouched: the runtime picks the pod IP from them.
			want, _ := ParseConf(data)
			if !reflect.DeepEqual(out["ips"], printed(t, want.PrevResult, ver)["ips"]) {
				t.Errorf("ips changed: %v", out["ips"])
			}
		})
	}
}

func TestAddFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		resolve  func(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error)
		wantCode uint
		wantMsg  string
	}{
		{"agent unreachable", func(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
			return nil, &agentapi.UnavailableError{Socket: "/s", Err: errors.New("connection refused")}
		}, types.ErrTryAgainLater, "zora agent unreachable at " + agentapi.DefaultSocket},
		{"agent error", func(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
			return nil, &agentapi.AgentError{Status: 422, Message: `secret "vpn" not found`}
		}, types.ErrInternal, `secret "vpn" not found`},
		{"corrupt plan", func(agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
			return &agentapi.ResolveResponse{Action: agentapi.ActionConfigure, Plan: &agentapi.WirePlan{}}, nil
		}, types.ErrInternal, "invalid plan"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, n := &fakeAgent{resolve: c.resolve}, &fakeNet{}
			_, _, err := newPlugin(a, n).Add(cmdArgs(stdin(t, "1.0.0", nil), podArgs))
			var cniErr *types.Error
			if !errors.As(err, &cniErr) || cniErr.Code != c.wantCode || !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("err = %v (%T); want CNI error %d containing %q", err, err, c.wantCode, c.wantMsg)
			}
			if len(n.applied) != 0 {
				t.Fatal("applied a plan despite the failure")
			}
		})
	}
}

func TestAddReportsApplyFailure(t *testing.T) {
	a := &fakeAgent{resolve: configure(goldenPlan(t))}
	n := &fakeNet{applyErr: errors.New("routes: file exists")}
	_, _, err := newPlugin(a, n).Add(cmdArgs(stdin(t, "1.0.0", nil), podArgs))
	if err == nil || !strings.Contains(err.Error(), "routes: file exists") {
		t.Fatalf("err = %v", err)
	}
	if len(a.reports) != 1 || a.reports[0].OK || !strings.Contains(a.reports[0].Error, "file exists") {
		t.Fatalf("reports = %+v", a.reports)
	}
}

func TestAddRefusesPrimaryInterfaceName(t *testing.T) {
	p := *goldenPlan(t)
	p.Link.Name = "eth0"
	a, n := &fakeAgent{resolve: configure(&p)}, &fakeNet{}
	_, _, err := newPlugin(a, n).Add(cmdArgs(stdin(t, "1.0.0", nil), podArgs))
	if err == nil || len(n.applied) != 0 || len(a.reports) != 1 || a.reports[0].OK {
		t.Fatalf("err = %v, applied %d, reports %+v", err, len(n.applied), a.reports)
	}
}

func TestAddRequiresChaining(t *testing.T) {
	_, _, err := newPlugin(&fakeAgent{}, &fakeNet{}).Add(cmdArgs(stdin(t, "1.0.0", map[string]any{"prevResult": nil}), podArgs))
	var cniErr *types.Error
	if !errors.As(err, &cniErr) || cniErr.Code != types.ErrInvalidNetworkConfig {
		t.Fatalf("err = %v", err)
	}
}

func TestDelNeverFails(t *testing.T) {
	withExtra := func(ver string) map[string]any {
		pr := prevResult(ver)
		pr["interfaces"] = append(pr["interfaces"].([]any), map[string]any{"name": "vpn0", "sandbox": testNetns})
		return map[string]any{"prevResult": pr}
	}
	cases := []struct {
		name      string
		data      []byte
		netns     string
		wantNames []string
	}{
		{"cached result names our link", stdin(t, "1.0.0", withExtra("1.0.0")), testNetns, []string{"wg0", "vpn0"}},
		{"0.4.0 cached result", stdin(t, "0.4.0", withExtra("0.4.0")), testNetns, []string{"wg0", "vpn0"}},
		{"no cached result", stdin(t, "1.0.0", map[string]any{"prevResult": nil}), testNetns, []string{"wg0"}},
		{"netns already gone", stdin(t, "1.0.0", nil), "", []string{"wg0"}},
		{"garbage config", []byte("{not json"), testNetns, []string{"wg0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &fakeNet{removeErr: errors.New("netlink exploded")}
			args := cmdArgs(c.data, podArgs)
			args.Netns = c.netns
			if err := newPlugin(&fakeAgent{}, n).Del(args); err != nil {
				t.Fatalf("Del failed: %v", err)
			}
			var names []string
			for _, r := range n.removed {
				names = append(names, r.plan.Link.Name)
				if r.netns != c.netns || r.plan.Link.BirthName != plan.BirthName(testContainerID) || r.plan.Mode != plan.ModeHost {
					t.Errorf("Remove(%q, %+v): want netns %q and the container's birth name", r.netns, r.plan.Link, c.netns)
				}
			}
			if !slices.Equal(names, c.wantNames) {
				t.Errorf("removed %v, want %v", names, c.wantNames)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	gp := goldenPlan(t)
	t.Run("excluded namespace needs no agent", func(t *testing.T) {
		a := &fakeAgent{}
		args := cmdArgs(stdin(t, "1.0.0", nil), strings.Replace(podArgs, "=apps", "=kube-system", 1))
		if err := newPlugin(a, &fakeNet{}).Check(args); err != nil || len(a.resolves) != 0 {
			t.Fatalf("err %v, resolves %d", err, len(a.resolves))
		}
	})
	t.Run("unannotated pod", func(t *testing.T) {
		n := &fakeNet{}
		if err := newPlugin(&fakeAgent{resolve: skip}, n).Check(cmdArgs(stdin(t, "1.0.0", nil), podArgs)); err != nil || len(n.verified) != 0 {
			t.Fatalf("err %v, verified %d", err, len(n.verified))
		}
	})
	t.Run("verifies the plan", func(t *testing.T) {
		n := &fakeNet{}
		if err := newPlugin(&fakeAgent{resolve: configure(gp)}, n).Check(cmdArgs(stdin(t, "1.0.0", nil), podArgs)); err != nil {
			t.Fatal(err)
		}
		if len(n.verified) != 1 || !reflect.DeepEqual(n.verified[0].plan, gp) {
			t.Fatalf("verified = %+v", n.verified)
		}
	})
	t.Run("reports drift", func(t *testing.T) {
		n := &fakeNet{verifyErr: errors.New("route blackhole 0.0.0.0/0 missing")}
		err := newPlugin(&fakeAgent{resolve: configure(gp)}, n).Check(cmdArgs(stdin(t, "1.0.0", nil), podArgs))
		if err == nil || !strings.Contains(err.Error(), "blackhole") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestGCDeletesOnlyOrphans(t *testing.T) {
	live, dead := plan.BirthName("live-container"), plan.BirthName("dead-container")
	n := &fakeNet{hostLinks: []string{live, dead}}
	data := stdin(t, "1.1.0", map[string]any{"prevResult": nil, "cni.dev/valid-attachments": []map[string]string{
		{"containerID": "live-container", "ifname": "eth0"},
	}})
	if err := newPlugin(&fakeAgent{}, n).GC(cmdArgs(data, "")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(n.deleted, []string{dead}) {
		t.Fatalf("deleted %v, want only %s", n.deleted, dead)
	}
}

func TestStatus(t *testing.T) {
	data := stdin(t, "1.1.0", map[string]any{"prevResult": nil})
	if err := newPlugin(&fakeAgent{}, &fakeNet{}).Status(cmdArgs(data, "")); err != nil {
		t.Fatalf("healthy agent: %v", err)
	}
	err := newPlugin(&fakeAgent{healthErr: errors.New("not synced")}, &fakeNet{}).Status(cmdArgs(data, ""))
	var cniErr *types.Error
	if !errors.As(err, &cniErr) || cniErr.Code != types.ErrPluginNotAvailable {
		t.Fatalf("err = %v", err)
	}
}

func TestParseConfDefaults(t *testing.T) {
	c, err := ParseConf([]byte(`{"cniVersion":"1.0.0","name":"n","type":"zora"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Socket != agentapi.DefaultSocket || !slices.Equal(c.ExcludeNamespaces, DefaultExcludeNamespaces) || c.timeout() != agentapi.DefaultTimeout {
		t.Fatalf("defaults: %+v", c)
	}
	c, err = ParseConf([]byte(`{"cniVersion":"1.0.0","name":"n","type":"zora","excludeNamespaces":[]}`))
	if err != nil || c.ExcludeNamespaces == nil || len(c.ExcludeNamespaces) != 0 {
		t.Fatalf("an explicit empty list must exclude nothing: %+v, %v", c, err)
	}
	if _, err := ParseConf([]byte(`{"cniVersion":"1.0.0","name":"n","type":"zora","timeoutSeconds":-1}`)); err == nil {
		t.Fatal("negative timeout accepted")
	}
}

func TestPodFromArgs(t *testing.T) {
	pod, ok := podFromArgs(podArgs)
	if !ok || pod != (agentapi.Pod{Namespace: "apps", Name: "vpn-client", UID: "uid-1"}) {
		t.Fatalf("got %+v, %v", pod, ok)
	}
	for _, a := range []string{"", "IgnoreUnknown=1", "K8S_POD_NAMESPACE=a", "K8S_POD_NAME=b"} {
		if _, ok := podFromArgs(a); ok {
			t.Errorf("%q parsed as a pod", a)
		}
	}
}
