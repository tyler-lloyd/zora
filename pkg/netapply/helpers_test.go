package netapply

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tyler-lloyd/zora/internal/testns"
	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

func TestMain(m *testing.M) { testns.Main(m) }

// Addresses used across the tests. The pod sits on 10.244.0.0/24 behind the
// "host" namespace, which also owns a Service IP and a node IP. The WireGuard
// peer and an "internet" server sit behind the host on 198.51.100.0/24.
const (
	podIP     = "10.244.0.5"
	podGW     = "10.244.0.1"
	podIP6    = "fd00:10:244::5"
	podGW6    = "fd00:10:244::1"
	serviceIP = "10.96.0.10"
	nodeIP    = "172.18.0.2"
	peerIP    = "198.51.100.1"
	hostIP    = "198.51.100.254"
	inetIP    = "203.0.113.1"
	inetIP6   = "2001:db8:113::1"
	tunPodIP  = "10.200.0.2"
	tunPodIP6 = "fd00:200::2"
)

var testCluster = plan.ClusterInfo{
	PodCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16")},
	ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")},
	NodeIPs:      []netip.Addr{netip.MustParseAddr(nodeIP)},
}

func genKey(t testing.TB) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// computePlan parses conf and computes its plan, failing the test on error.
func computePlan(t testing.TB, conf string, in plan.Input) *plan.Plan {
	t.Helper()
	cfg, err := wgconfig.Parse([]byte(conf))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, conf)
	}
	in.Config = cfg
	p, err := plan.Compute(in)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return p
}

// fullTunnelConf is a dual-stack full-tunnel config pointing at the peer.
func fullTunnelConf(podKey, peerPub wgtypes.Key) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32, %s/128

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s:51820
PersistentKeepalive = 25
`, podKey, tunPodIP, tunPodIP6, peerPub, peerIP)
}

// newPod creates a pod namespace with an eth0 that looks like a primary
// CNI's: addresses, a default route, the pod CIDR, and a Calico-style
// point-to-point gateway route. Its uplink is a dummy, so nothing is
// reachable; use newWorld for traffic.
func newPod(t testing.TB) *testns.NS {
	t.Helper()
	pod := testns.New(t, "pod")
	pod.Dummy(t, "eth0")
	configurePodUplink(t, pod)
	return pod
}

func configurePodUplink(t testing.TB, pod *testns.NS) {
	t.Helper()
	pod.Addr(t, "eth0", podIP+"/24")
	pod.Addr(t, "eth0", podIP6+"/64")
	pod.Route(t, "0.0.0.0/0", podGW, "eth0")
	pod.Route(t, "::/0", podGW6, "eth0")
	pod.Route(t, "10.244.0.0/16", podGW, "eth0")
	pod.Route(t, "169.254.1.1/32", "", "eth0")
}

// snapshot renders a namespace's links, addresses, routes (all tables) and
// rules as sorted lines, for before/after comparisons.
func snapshot(t testing.TB, ns *testns.NS) []string {
	t.Helper()
	h := ns.Handle
	var out []string
	links, err := h.LinkList()
	ns.Must(t, err)
	names := map[int]string{}
	for _, l := range links {
		a := l.Attrs()
		names[a.Index] = a.Name
		out = append(out, fmt.Sprintf("link %s type=%s mtu=%d up=%v", a.Name, l.Type(), a.MTU, a.Flags&net.FlagUp != 0))
	}
	addrs, err := h.AddrList(nil, netlink.FAMILY_ALL)
	ns.Must(t, err)
	for _, a := range addrs {
		out = append(out, fmt.Sprintf("addr %s dev=%s", a.IPNet, names[a.LinkIndex]))
	}
	routes, err := h.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	ns.Must(t, err)
	for _, r := range routes {
		out = append(out, fmt.Sprintf("route table=%d type=%d dst=%v dev=%s gw=%v metric=%d", r.Table, r.Type, r.Dst, names[r.LinkIndex], r.Gw, r.Priority))
	}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := h.RuleList(fam)
		ns.Must(t, err)
		for _, r := range rules {
			out = append(out, fmt.Sprintf("rule fam=%d prio=%d table=%d dst=%v mark=%#x invert=%v suppress=%d", fam, r.Priority, r.Table, r.Dst, r.Mark, r.Invert, r.SuppressPrefixlen))
		}
	}
	slices.Sort(out)
	return out
}

func assertSameState(t testing.TB, what string, before, after []string) {
	t.Helper()
	if slices.Equal(before, after) {
		return
	}
	var b strings.Builder
	for _, l := range before {
		if !slices.Contains(after, l) {
			b.WriteString("  - " + l + "\n")
		}
	}
	for _, l := range after {
		if !slices.Contains(before, l) {
			b.WriteString("  + " + l + "\n")
		}
	}
	t.Fatalf("%s: namespace state changed:\n%s", what, b.String())
}
