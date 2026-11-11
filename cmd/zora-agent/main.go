// Command zora-agent is zora's per-node daemon. See pkg/agent.
//
//	zora-agent run        run the agent (the DaemonSet's command)
//	zora-agent uninstall  remove zora from this node's CNI config and bin dir
//	zora-agent pre-delete delete the agent DaemonSet and wait for every node
//	                      to uninstall (the Helm chart's pre-delete hook)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/tyler-lloyd/zora/pkg/agent"
	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/repair"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, os.Args[1:]); err != nil {
		log.Error("zora-agent failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, args []string) error {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if cmd != "run" && cmd != "uninstall" && cmd != "pre-delete" {
		return fmt.Errorf("unknown command %q: use run, uninstall or pre-delete", cmd)
	}

	fs := flag.NewFlagSet("zora-agent "+cmd, flag.ContinueOnError)
	var o agent.Options
	var podCIDRs, serviceCIDRs, extraExcludes, excludeNS, hostModeNS, repairAction, kubeconfig string
	fs.StringVar(&o.NodeName, "node-name", os.Getenv("NODE_NAME"), "this node's name")
	fs.StringVar(&o.Socket, "socket", agentapi.DefaultSocket, "unix socket to serve the CNI plugin on")
	fs.StringVar(&o.PluginSocket, "plugin-socket", "", "the socket's path on the host, if different from --socket")
	fs.StringVar(&o.CNIConfDir, "cni-conf-dir", "/host/etc/cni/net.d", "the host's CNI config directory, as mounted here")
	fs.StringVar(&o.CNIBinDir, "cni-bin-dir", "/host/opt/cni/bin", "the host's CNI plugin directory, as mounted here")
	fs.StringVar(&o.PluginSource, "plugin-source", "/usr/local/bin/zora-cni", "the zora-cni binary to install")
	fs.StringVar(&podCIDRs, "pod-cidrs", "", "comma-separated cluster pod CIDRs, kept out of every tunnel")
	fs.StringVar(&serviceCIDRs, "service-cidrs", "", "comma-separated cluster service CIDRs, kept out of every tunnel; detected from the cluster on Kubernetes 1.33+ when unset")
	fs.StringVar(&extraExcludes, "extra-excludes", "", "comma-separated extra CIDRs kept out of every tunnel (e.g. NodeLocal DNS)")
	fs.StringVar(&excludeNS, "exclude-namespaces", "kube-system", "comma-separated namespaces zora never touches")
	fs.StringVar(&hostModeNS, "host-mode-namespaces", "", "comma-separated namespaces allowed to use host mode (bypasses NetworkPolicy for tunnel traffic)")
	fs.StringVar(&repairAction, "repair-action", string(repair.ActionDelete), "what to do with pods running without their tunnel: delete, event or none")
	fs.DurationVar(&o.RepairGrace, "repair-grace", time.Minute, "how long a pod may run without its tunnel before repair")
	fs.DurationVar(&o.RepairInterval, "repair-interval", 30*time.Second, "how often to look for pods to repair")
	fs.DurationVar(&o.Resync, "resync", 30*time.Second, "how often to re-check the CNI config without a file event")
	fs.StringVar(&o.HealthAddr, "health-addr", ":9809", "address for /healthz and /readyz; empty disables")
	fs.StringVar(&o.DaemonSetNamespace, "daemonset-namespace", os.Getenv("POD_NAMESPACE"), "namespace of the agent's DaemonSet")
	fs.StringVar(&o.DaemonSetName, "daemonset-name", "", "name of the agent's DaemonSet; when it is deleted the agent uninstalls on exit")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig file; default is in-cluster configuration")
	timeout := fs.Duration("timeout", 5*time.Minute, "pre-delete: how long to wait for every node to uninstall")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var err error
	if o.Cluster.PodCIDRs, err = parsePrefixes("--pod-cidrs", podCIDRs); err != nil {
		return err
	}
	if o.Cluster.ServiceCIDRs, err = parsePrefixes("--service-cidrs", serviceCIDRs); err != nil {
		return err
	}
	if o.Cluster.ExtraExcludes, err = parsePrefixes("--extra-excludes", extraExcludes); err != nil {
		return err
	}
	o.ExcludeNamespaces = splitList(excludeNS)
	if o.ExcludeNamespaces == nil {
		o.ExcludeNamespaces = []string{} // explicitly none
	}
	o.HostModeNamespaces = splitList(hostModeNS)
	if o.RepairAction, err = repair.ParseAction(repairAction); err != nil {
		return err
	}

	if cmd == "uninstall" {
		// Needs no API access: it only edits files on this node.
		if o.NodeName == "" {
			o.NodeName = "uninstall"
		}
		a, err := agent.New(o, nil, log)
		if err != nil {
			return err
		}
		return a.Uninstall()
	}

	if cmd == "pre-delete" {
		if o.DaemonSetName == "" || o.DaemonSetNamespace == "" {
			return fmt.Errorf("pre-delete needs --daemonset-name and --daemonset-namespace")
		}
		cfg, err := restConfig(kubeconfig)
		if err != nil {
			return err
		}
		client, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		log.Info("deleting the agent DaemonSet and waiting for nodes to uninstall", "daemonset", o.DaemonSetNamespace+"/"+o.DaemonSetName)
		return agent.RemoveDaemonSet(ctx, client, o.DaemonSetNamespace, o.DaemonSetName, 2*time.Second)
	}

	if len(o.Cluster.PodCIDRs) == 0 {
		// Without it, a full-tunnel pod would send traffic for other pods
		// into its tunnel. Refuse to start rather than break pods quietly.
		return fmt.Errorf("--pod-cidrs is required")
	}
	cfg, err := restConfig(kubeconfig)
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	a, err := agent.New(o, client, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return a.Run(ctx)
}

func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func splitList(s string) []string {
	var out []string
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parsePrefixes(flagName, s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(s) {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a CIDR", flagName, item)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
