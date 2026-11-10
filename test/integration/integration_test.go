// Package integration runs the real zora-cni binary the way a container
// runtime does: libcni executes a conflist in which zora is chained after the
// reference bridge or ptp plugin with host-local IPAM, against throwaway
// network namespaces, with an in-process fake agent on a unix socket.
//
// This tier catches what unit tests can't: the CNI protocol across a process
// boundary (stdin, env, stdout, exit codes, error JSON), version conversion
// of real prevResults, interaction with real primary plugins, and the
// binary's own wiring.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tyler-lloyd/zora/internal/testns"
	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

func TestMain(m *testing.M) { testns.Main(m) }

const (
	peerIP  = "198.51.100.1"
	hostIP  = "198.51.100.254"
	inetIP  = "203.0.113.1"
	podsV4  = "10.22.0.0/16" // bridge
	podsPtp = "10.23.0.0/16" // ptp
)

// 0.3.1 matters: kindnet, flannel, Cilium and Calico all write it.
var cniVersions = []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"}

// buildPlugins compiles zora-cni and the reference plugins (pinned in go.mod
// as tools) into a temporary CNI bin dir, once per test binary.
var buildPlugins = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "zora-cni-bin-")
	if err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-o", dir+string(filepath.Separator),
		"github.com/tyler-lloyd/zora/cmd/zora-cni",
		"github.com/containernetworking/plugins/plugins/main/bridge",
		"github.com/containernetworking/plugins/plugins/main/ptp",
		"github.com/containernetworking/plugins/plugins/ipam/host-local",
	)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		// The build runs inside a namespace with no network access.
		return "", fmt.Errorf("go build (if modules are missing, run `go mod download` first): %w\n%s", err, out)
	}
	// The binary is named after its type in the conflist.
	return dir, os.Rename(filepath.Join(dir, "zora-cni"), filepath.Join(dir, "zora"))
})

// fakeAgent answers Resolve from a table of plans keyed by pod name.
type fakeAgent struct {
	mu      sync.Mutex
	plans   map[string]*plan.Plan
	reports []agentapi.ReportRequest
}

func (a *fakeAgent) Resolve(_ context.Context, req agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.plans[req.Pod.Name]
	if !ok {
		return &agentapi.ResolveResponse{Action: agentapi.ActionSkip}, nil
	}
	return &agentapi.ResolveResponse{Action: agentapi.ActionConfigure, Plan: agentapi.EncodePlan(p)}, nil
}

func (a *fakeAgent) Report(_ context.Context, req agentapi.ReportRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reports = append(a.reports, req)
	return nil
}

func (a *fakeAgent) Healthy(context.Context) error { return nil }

func (a *fakeAgent) set(name string, p *plan.Plan) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.plans[name] = p
}

func (a *fakeAgent) reportFor(name string) (agentapi.ReportRequest, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.reports) - 1; i >= 0; i-- {
		if a.reports[i].Pod.Name == name {
			return a.reports[i], true
		}
	}
	return agentapi.ReportRequest{}, false
}

// world is a node (the test process's namespace, where the runtime execs
// plugins) plus a WireGuard peer and an "internet" server behind it. The
// node can also reach the internet server directly, so a pod's traffic that
// leaked in the clear would arrive too; the server's view of the source
// address tells the paths apart.
type world struct {
	host, peer *testns.NS
	peerKey    wgtypes.Key
	cni        *libcni.CNIConfig
	ipamDir    string
	agent      *fakeAgent
	socket     string
	nextTunnel int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	testns.RequireWireGuard(t)
	binDir, err := buildPlugins()
	if err != nil {
		t.Fatal(err)
	}
	w := &world{
		host: testns.Current(t), peer: testns.New(t, "peer"), peerKey: genKey(t),
		ipamDir: t.TempDir(), agent: &fakeAgent{plans: map[string]*plan.Plan{}}, nextTunnel: 2,
	}
	w.cni = libcni.NewCNIConfigWithCacheDir([]string{binDir}, t.TempDir(), nil)

	testns.Veth(t, w.host, "veth-peer", w.peer, "eth0")
	w.host.Addr(t, "veth-peer", hostIP+"/24")
	w.peer.Addr(t, "eth0", peerIP+"/24")
	w.peer.Route(t, podsV4, hostIP, "eth0")
	w.peer.Route(t, podsPtp, hostIP, "eth0")
	w.host.Sysctl(t, "net.ipv4.ip_forward", "1")
	w.host.Route(t, inetIP+"/32", peerIP, "veth-peer")
	w.peer.Dummy(t, "inet")
	w.peer.Addr(t, "inet", inetIP+"/32")

	w.peer.Must(t, w.peer.Handle.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg0"}}))
	w.peer.Addr(t, "wg0", "10.200.0.1/24")
	port := 51820
	w.wg(t, wgtypes.Config{PrivateKey: &w.peerKey, ListenPort: &port})
	w.peer.Must(t, w.peer.Handle.LinkSetUp(w.peer.Link(t, "wg0")))
	testns.ServeWhoami(t, w.peer, ":8080")

	w.socket = filepath.Join(t.TempDir(), "run", "zora.sock")
	l, err := agentapi.Listen(w.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := agentapi.NewServer(w.agent)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return w
}

func genKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (w *world) wg(t *testing.T, cfg wgtypes.Config) {
	t.Helper()
	w.peer.Do(t, func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		return c.ConfigureDevice("wg0", cfg)
	})
}

// tunnelFor registers a pod with the peer and returns the plan the agent
// should hand out for it, and the pod's tunnel address.
func (w *world) tunnelFor(t *testing.T, mode plan.Mode, containerID string) (*plan.Plan, string) {
	t.Helper()
	podKey := genKey(t)
	tunIP := fmt.Sprintf("10.200.0.%d", w.nextTunnel)
	w.nextTunnel++
	w.wg(t, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:  podKey.PublicKey(),
		AllowedIPs: []net.IPNet{*testns.IPNet(netip.MustParsePrefix(tunIP + "/32"))},
	}}})
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:51820\n",
		podKey, tunIP, w.peerKey.PublicKey(), peerIP)
	cfg, err := wgconfig.Parse([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.Compute(plan.Input{
		Config: cfg, Mode: mode, ContainerID: containerID,
		Cluster: plan.ClusterInfo{
			PodCIDRs:     []netip.Prefix{netip.MustParsePrefix(podsV4), netip.MustParsePrefix(podsPtp)},
			ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, tunIP
}

// conflist is a CNI network config list with zora chained after primary.
type conflistOpts struct {
	version, primary string
	socket           string
	withZora         bool
	capabilities     bool // declare the pod-annotations capability
}

func (w *world) conflist(t *testing.T, o conflistOpts) *libcni.NetworkConfigList {
	t.Helper()
	ipam := map[string]any{
		"type": "host-local", "dataDir": w.ipamDir,
		"routes": []map[string]string{{"dst": "0.0.0.0/0"}},
	}
	var primary map[string]any
	switch o.primary {
	case "bridge":
		ipam["ranges"] = [][]map[string]string{{{"subnet": podsV4}}}
		primary = map[string]any{"type": "bridge", "bridge": "cni0", "isGateway": true, "ipMasq": false, "ipam": ipam}
	case "ptp":
		ipam["ranges"] = [][]map[string]string{{{"subnet": podsPtp}}}
		primary = map[string]any{"type": "ptp", "ipMasq": false, "ipam": ipam}
	default:
		t.Fatalf("unknown primary %q", o.primary)
	}
	plugins := []any{primary}
	if o.withZora {
		z := map[string]any{"type": "zora", "socket": o.socket}
		if o.capabilities {
			z["capabilities"] = map[string]bool{"io.kubernetes.cri.pod-annotations": true}
		}
		plugins = append(plugins, z)
	}
	b, err := json.Marshal(map[string]any{"cniVersion": o.version, "name": "k8s-pod-network-" + o.primary, "plugins": plugins})
	if err != nil {
		t.Fatal(err)
	}
	list, err := libcni.ConfListFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func runtimeConf(pod *testns.NS, namespace, name, containerID string) *libcni.RuntimeConf {
	return &libcni.RuntimeConf{
		ContainerID: containerID, NetNS: pod.Path, IfName: "eth0",
		Args: [][2]string{
			{"IgnoreUnknown", "1"},
			{"K8S_POD_NAMESPACE", namespace},
			{"K8S_POD_NAME", name},
			{"K8S_POD_INFRA_CONTAINER_ID", containerID},
			{"K8S_POD_UID", "uid-" + containerID},
		},
	}
}

func asCurrent(t *testing.T, r types.Result) *current.Result {
	t.Helper()
	c, err := current.NewResultFromResult(r)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wireguardLinks(t *testing.T, ns *testns.NS) []string {
	t.Helper()
	links, err := ns.Handle.LinkList()
	ns.Must(t, err)
	var out []string
	for _, l := range links {
		if l.Type() == "wireguard" {
			out = append(out, l.Attrs().Name)
		}
	}
	return out
}

// allocatedIPs lists host-local's allocations for a network.
func (w *world) allocatedIPs(t *testing.T, network string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(w.ipamDir, network))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var ips []string
	for _, e := range entries {
		if net.ParseIP(e.Name()) != nil {
			ips = append(ips, e.Name())
		}
	}
	return ips
}
