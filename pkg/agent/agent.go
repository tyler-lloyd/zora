// Package agent is zora-agent: the per-node daemon that installs the CNI
// plugin, keeps it chained into the primary CNI's config, answers the
// plugin's questions, and repairs pods that missed it.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/install"
	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/repair"
	"github.com/tyler-lloyd/zora/pkg/resolver"
)

// Options configures the agent.
type Options struct {
	NodeName string

	// Socket is where the agent listens, as the agent sees it.
	// PluginSocket is the same socket as the plugin (on the host) sees
	// it; it defaults to Socket.
	Socket       string
	PluginSocket string

	// CNIConfDir and CNIBinDir are the host's CNI directories as mounted
	// into the agent. PluginSource is the zora-cni binary to install.
	CNIConfDir   string
	CNIBinDir    string
	PluginSource string

	Cluster            plan.ClusterInfo
	ExcludeNamespaces  []string
	HostModeNamespaces []string

	RepairAction   repair.Action
	RepairGrace    time.Duration
	RepairInterval time.Duration
	// Resync is how often the CNI config is re-checked without an event.
	Resync time.Duration

	// HealthAddr serves /healthz and /readyz. Empty disables it.
	HealthAddr string

	// DaemonSetNamespace and DaemonSetName identify the agent's own
	// DaemonSet; on shutdown the agent uninstalls only if it is gone.
	DaemonSetNamespace string
	DaemonSetName      string
}

func (o *Options) defaults() error {
	if o.NodeName == "" {
		return errors.New("node name is required")
	}
	if o.Socket == "" {
		o.Socket = agentapi.DefaultSocket
	}
	if o.PluginSocket == "" {
		o.PluginSocket = o.Socket
	}
	if o.CNIConfDir == "" || o.CNIBinDir == "" || o.PluginSource == "" {
		return errors.New("CNI conf dir, CNI bin dir and plugin source are required")
	}
	if o.ExcludeNamespaces == nil {
		o.ExcludeNamespaces = []string{"kube-system"}
	}
	if o.RepairAction == "" {
		o.RepairAction = repair.ActionDelete
	}
	if o.RepairGrace <= 0 {
		o.RepairGrace = time.Minute
	}
	if o.RepairInterval <= 0 {
		o.RepairInterval = 30 * time.Second
	}
	if o.Resync <= 0 {
		o.Resync = 30 * time.Second
	}
	return nil
}

// Agent is a running (or about to run) zora-agent.
type Agent struct {
	opts   Options
	client kubernetes.Interface
	log    *slog.Logger

	synced    atomic.Bool
	serving   atomic.Bool
	installed atomic.Bool
	nodeIPs   atomic.Pointer[[]netip.Addr]
	// Resolver is exposed for tests; nil until Run has started it.
	Resolver *resolver.Resolver
}

// New validates opts and returns an agent.
func New(opts Options, client kubernetes.Interface, log *slog.Logger) (*Agent, error) {
	if err := opts.defaults(); err != nil {
		return nil, err
	}
	return &Agent{opts: opts, client: client, log: log}, nil
}

func (a *Agent) pluginPath() string { return filepath.Join(a.opts.CNIBinDir, install.PluginType) }

func (a *Agent) reconciler() *install.Reconciler {
	return &install.Reconciler{
		Dir: a.opts.CNIConfDir,
		Entry: install.Entry{
			Socket:            a.opts.PluginSocket,
			ExcludeNamespaces: a.opts.ExcludeNamespaces,
		},
		FS: install.OSFS{},
	}
}

// Ready reports whether this node can give pods WireGuard interfaces: the
// plugin is chained into the CNI config and the agent can answer it.
func (a *Agent) Ready() error {
	switch {
	case !a.synced.Load():
		return errors.New("pod cache has not synced")
	case !a.serving.Load():
		return errors.New("not serving the plugin socket yet")
	case !a.installed.Load():
		return errors.New("not chained into the CNI config yet")
	}
	return nil
}

// Run runs the agent until ctx ends, then cleans up.
func (a *Agent) Run(ctx context.Context) error {
	o := a.opts
	changed, err := install.InstallBinary(o.PluginSource, a.pluginPath())
	if err != nil {
		return fmt.Errorf("installing the CNI plugin: %w", err)
	}
	a.log.Info("CNI plugin binary", "path", a.pluginPath(), "updated", changed)

	// Pods on this node only.
	factory := informers.NewSharedInformerFactoryWithOptions(a.client, 0,
		informers.WithTweakListOptions(func(lo *metav1.ListOptions) {
			lo.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", o.NodeName).String()
		}))
	podInformer := factory.Core().V1().Pods()
	informer := podInformer.Informer()
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return ctx.Err()
	}
	a.synced.Store(true)

	broadcaster := record.NewBroadcaster()
	defer broadcaster.Shutdown()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: a.client.CoreV1().Events("")})
	events := broadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "zora-agent", Host: o.NodeName})

	a.refreshNodeIPs(ctx)
	res := &resolver.Resolver{
		Client: a.client, Pods: podInformer.Lister(), Synced: informer.HasSynced,
		Events: events, DNS: net.DefaultResolver,
		Config: resolver.Config{
			Cluster:            o.Cluster,
			HostModeNamespaces: o.HostModeNamespaces,
			NodeIPs: func() []netip.Addr {
				if p := a.nodeIPs.Load(); p != nil {
					return *p
				}
				return nil
			},
		},
	}
	a.Resolver = res

	// Serve the plugin before chaining it in, so the first ADD that
	// reaches zora finds the agent.
	listener, err := agentapi.Listen(o.Socket)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", o.Socket, err)
	}
	server := agentapi.NewServer(res)
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()
	a.serving.Store(true)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if o.HealthAddr != "" {
		health := &http.Server{Addr: o.HealthAddr, Handler: a.healthHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := health.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				a.log.Error("health server", "err", err)
			}
		}()
		defer func() { _ = health.Close() }()
	}

	if err := os.MkdirAll(o.CNIConfDir, 0o755); err != nil { // #nosec G301 -- the CNI conf dir is world-readable
		return err
	}
	watch, err := install.Watch(ctx, o.CNIConfDir)
	if err != nil {
		return err
	}
	resync := time.NewTicker(o.Resync)
	defer resync.Stop()
	var last string
	reconcilerDone := make(chan struct{})
	go func() {
		defer close(reconcilerDone)
		a.reconcile(ctx, watch, resync.C, &last)
	}()

	rep := &repair.Controller{
		Client: a.client, Pods: podInformer.Lister(), Reports: res, Events: events,
		Node: o.NodeName, Action: o.RepairAction, Grace: o.RepairGrace,
		ExcludeNamespaces: o.ExcludeNamespaces, Installed: a.installed.Load,
	}
	repairTick := time.NewTicker(o.RepairInterval)
	defer repairTick.Stop()

	a.log.Info("zora-agent running", "node", o.NodeName, "socket", o.Socket)
	for {
		select {
		case <-ctx.Done():
			// A reconcile pass still in flight would re-install what an
			// uninstall is about to remove, so let it finish first.
			<-reconcilerDone
			return a.shutdown()
		case err := <-serverErr:
			return fmt.Errorf("plugin socket server stopped: %w", err)
		case <-repairTick.C:
			a.refreshNodeIPs(ctx)
			outcomes, err := rep.RunOnce(ctx)
			for _, oc := range outcomes {
				a.log.Info("repair", "pod", oc.Pod, "action", oc.Action)
			}
			if err != nil && ctx.Err() == nil {
				a.log.Error("repair", "err", err)
			}
		}
	}
}

// reconcile keeps zora chained into the CNI config until ctx ends.
func (a *Agent) reconcile(ctx context.Context, watch <-chan struct{}, resync <-chan time.Time, last *string) {
	o := a.opts
	a.reconciler().Run(ctx, watch, resync, func(st install.Status, err error) {
		a.installed.Store(err == nil && st.Installed)
		// The binary can be removed behind our back too.
		if _, berr := install.InstallBinary(o.PluginSource, a.pluginPath()); berr != nil {
			a.log.Error("re-installing the CNI plugin", "err", berr)
		}
		line := fmt.Sprintf("%v|%s|%s|%v", st.Installed, st.Primary, st.Reason, err)
		if len(st.Wrote) == 0 && line == *last {
			return // steady state: stay quiet
		}
		*last = line
		if err != nil {
			a.log.Error("CNI config", "err", err)
			return
		}
		a.log.Info("CNI config", "installed", st.Installed, "primary", st.Primary, "reason", st.Reason, "wrote", st.Wrote)
	})
}

func (a *Agent) healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.Ready(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// refreshNodeIPs reads the node's addresses, which pods must keep reaching
// outside their tunnel (the kubelet probes from them).
func (a *Agent) refreshNodeIPs(ctx context.Context) {
	node, err := a.client.CoreV1().Nodes().Get(ctx, a.opts.NodeName, metav1.GetOptions{})
	if err != nil {
		if ctx.Err() == nil {
			a.log.Warn("reading node addresses", "err", err)
		}
		return
	}
	var ips []netip.Addr
	for _, addr := range node.Status.Addresses {
		if addr.Type != corev1.NodeInternalIP && addr.Type != corev1.NodeExternalIP {
			continue
		}
		if ip, err := netip.ParseAddr(addr.Address); err == nil {
			ips = append(ips, ip.Unmap())
		}
	}
	a.nodeIPs.Store(&ips)
}

// shutdown decides whether this is an uninstall. A rolling update or node
// drain must leave the plugin in place: pods on the node keep their config,
// and the next agent picks up where this one left off. Only when the
// DaemonSet itself is gone does the agent remove zora from the node, since
// a chained plugin without its agent would block every new pod.
func (a *Agent) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if !a.daemonSetGone(ctx) {
		a.log.Info("shutting down; leaving the CNI plugin installed")
		return nil
	}
	a.log.Info("the DaemonSet is being deleted; uninstalling from this node")
	return a.Uninstall()
}

func (a *Agent) daemonSetGone(ctx context.Context) bool {
	if a.opts.DaemonSetName == "" {
		return false
	}
	ds, err := a.client.AppsV1().DaemonSets(a.opts.DaemonSetNamespace).Get(ctx, a.opts.DaemonSetName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true
	}
	// If the API server can't be asked, assume a restart: leaving zora
	// installed is recoverable, removing it from a healthy node is not.
	return err == nil && ds.DeletionTimestamp != nil
}

// Uninstall removes zora from the node's CNI config, then removes the
// plugin binary. The order matters: a config that names a missing binary
// would fail every pod.
func (a *Agent) Uninstall() error {
	wrote, err := a.reconciler().Uninstall()
	if err != nil {
		return fmt.Errorf("removing zora from the CNI config: %w", err)
	}
	a.installed.Store(false)
	if err := os.Remove(a.pluginPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a.log.Info("uninstalled", "configs", wrote, "binary", a.pluginPath())
	return nil
}
