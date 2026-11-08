package netapply

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

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

// debugDump returns the namespace's network state as ip(8) and wg(8) print
// it, for failure messages. Missing tools are skipped.
func debugDump(ns *testns.NS) string {
	var b strings.Builder
	for _, args := range [][]string{
		{"ip", "-d", "link"}, {"ip", "addr"}, {"ip", "rule"}, {"ip", "-6", "rule"},
		{"ip", "route", "show", "table", "all"}, {"ip", "-6", "route", "show", "table", "all"},
		{"wg", "show", "all"}, {"sysctl", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.src_valid_mark"},
	} {
		cmd := exec.Command("nsenter", append([]string{"--net=" + ns.Path, "--"}, args...)...)
		out, err := cmd.CombinedOutput()
		if errors.Is(err, exec.ErrNotFound) {
			continue
		}
		fmt.Fprintf(&b, "--- %s: %s\n%s", ns.Name, strings.Join(args, " "), out)
	}
	return b.String()
}

// serveWhoami listens on addr inside ns and answers every connection with
// the client's source address, so tests can tell tunnelled traffic (source
// = tunnel address) from traffic that took another path.
func serveWhoami(t testing.TB, ns *testns.NS, addr string) {
	t.Helper()
	var l net.Listener
	ns.Do(t, func() (err error) {
		l, err = net.Listen("tcp", addr)
		return err
	})
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			_, _ = fmt.Fprintln(c, host)
			_ = c.Close()
		}
	}()
}

// whoami connects from ns to addr (optionally from local) and returns the
// source address the server saw.
func whoami(t testing.TB, ns *testns.NS, addr, local string) (string, error) {
	t.Helper()
	var reply string
	var dialErr error
	ns.Do(t, func() error {
		d := net.Dialer{Timeout: 3 * time.Second}
		if local != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
		}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			dialErr = err
			return nil
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		reply, err = bufio.NewReader(c).ReadString('\n')
		dialErr = err
		return nil
	})
	return strings.TrimSpace(reply), dialErr
}

func mustWhoami(t testing.TB, ns *testns.NS, addr, local, wantSource, why string) {
	t.Helper()
	got, err := whoami(t, ns, addr, local)
	if err != nil {
		t.Fatalf("%s: connecting from %s to %s: %v\n%s", why, ns.Name, addr, err, debugDump(ns))
	}
	if got != wantSource {
		t.Fatalf("%s: server %s saw source %s, want %s\n%s", why, addr, got, wantSource, debugDump(ns))
	}
}

func mustNotConnect(t testing.TB, ns *testns.NS, addr, why string) {
	t.Helper()
	got, err := whoami(t, ns, addr, "")
	if err == nil {
		t.Fatalf("%s: connection from %s to %s succeeded (server saw %s); it must fail", why, ns.Name, addr, got)
	}
	var errno unix.Errno
	if !errors.As(err, &errno) && !strings.Contains(err.Error(), "timeout") {
		t.Logf("%s: connection failed as required: %v", why, err)
	}
}
