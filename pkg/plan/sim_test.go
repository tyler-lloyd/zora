package plan

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/tyler-lloyd/zora/internal/routesim"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

// This file checks the safety properties zora promises against a model of
// Linux policy routing (internal/routesim), on every golden case and on
// thousands of randomly generated configs:
//
//  1. Cluster carve-outs always leave via the uplink, marked or not.
//  2. In pod mode, the WireGuard socket's own (marked) packets to every peer
//     endpoint leave via the uplink: the tunnel can't loop.
//  3. Traffic to any AllowedIPs destination outside the carve-outs enters
//     the tunnel.
//  4. Kill switch: with the WireGuard link gone, that same traffic is
//     dropped, never sent out of the uplink in the clear.
//  5. Traffic to destinations the config doesn't claim is left alone.
//  6. Specific routes the primary CNI installed (link-local, gateways) win
//     over the tunnel, even when ClusterInfo doesn't list them.
//  7. In pod mode, replies to the WireGuard socket pass strict IPv4
//     rp_filter: their reverse path is the uplink.
//
// The model itself is checked against the real kernel by the netns tests in
// pkg/netapply; this file exists so the properties are cheap enough to check
// exhaustively on every `go test`.

// primaryRoutes are specific routes real primary CNIs put in the pod's main
// table that ClusterInfo does not mention: the IPv6 link-local subnet (every
// pod has it) and a point-to-point gateway (Calico uses 169.254.1.1).
var primaryRoutes = []netip.Prefix{
	netip.MustParsePrefix("fe80::/64"),
	netip.MustParsePrefix("169.254.1.1/32"),
}

// newSim models the pod netns the plan would produce. The main table holds
// what the primary CNI typically installs (a default route, the pod CIDR and
// primaryRoutes via the uplink) plus the kernel's connected routes for the
// plan's addresses. linkUp=false models the WireGuard link having been
// deleted.
func newSim(in Input, p *Plan, linkUp bool) *routesim.Netns {
	uplink := cmpOr(in.UplinkName, DefaultUplinkName)
	routes := []routesim.Route{
		{Table: MainTable, Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: uplink},
		{Table: MainTable, Dst: netip.MustParsePrefix("::/0"), Dev: uplink},
	}
	for _, pc := range append(slices.Clone(in.Cluster.PodCIDRs), primaryRoutes...) {
		routes = append(routes, routesim.Route{Table: MainTable, Dst: pc.Masked(), Dev: uplink})
	}
	if linkUp {
		for _, a := range p.Addresses {
			if a.Bits() < a.Addr().BitLen() {
				routes = append(routes, routesim.Route{Table: MainTable, Dst: a.Masked(), Dev: p.Link.Name})
			}
		}
	}
	for _, r := range p.Routes {
		if !linkUp && r.Dev == p.Link.Name {
			continue // routes via a deleted link disappear with it
		}
		routes = append(routes, routesim.Route{
			Table: r.Table, Dst: r.Dst, Dev: r.Dev, Blackhole: r.Type == RouteBlackhole, Metric: r.Metric,
		})
	}
	var rules []routesim.Rule
	for _, r := range p.Rules {
		rules = append(rules, routesim.Rule{
			Priority: r.Priority, IPv6: r.Family == IPv6, Dst: r.Dst, Mark: r.Mark,
			Invert: r.Invert, IPProto: r.IPProto, SPort: r.SPort, Table: r.Table,
			SuppressPrefixLength: r.SuppressPrefixLength,
		})
	}
	rules = append(rules,
		routesim.Rule{Priority: 32766, Table: MainTable},
		routesim.Rule{Priority: 32766, IPv6: true, Table: MainTable})
	return routesim.New(routes, rules)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// probes returns interesting destinations for a plan.
func probes(rng *rand.Rand, in Input, p *Plan) []netip.Addr {
	var prefixes []netip.Prefix
	prefixes = append(prefixes, collectCarveOuts(in.Cluster)...)
	for _, peer := range p.Device.Peers {
		prefixes = append(prefixes, peer.AllowedIPs...)
	}
	prefixes = append(prefixes, p.Addresses...)
	prefixes = append(prefixes, primaryRoutes...)
	var endpoints []netip.Addr
	for _, peer := range p.Device.Peers {
		if peer.Endpoint != nil {
			endpoints = append(endpoints, peer.Endpoint.Addr())
		}
	}
	return routesim.Probes(rng, prefixes, endpoints...)
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Masked().Contains(a) {
			return true
		}
	}
	return false
}

// checkInvariants asserts the five properties for one input and its plan.
func checkInvariants(t testing.TB, in Input, p *Plan) {
	t.Helper()
	// The routing properties only apply when zora manages routes.
	if in.Config.Interface.Table.Mode == wgconfig.TableOff {
		if len(p.Routes) != 0 || len(p.Rules) != 0 {
			t.Fatalf("Table=off produced routes or rules: %+v %+v", p.Routes, p.Rules)
		}
		return
	}
	rng := rand.New(rand.NewPCG(1, 2))
	uplink := cmpOr(in.UplinkName, DefaultUplinkName)
	up, down := newSim(in, p, true), newSim(in, p, false)
	carveOuts := collectCarveOuts(in.Cluster)
	var tunnel []netip.Prefix
	for _, r := range p.Routes {
		if r.Type == RouteUnicast {
			tunnel = append(tunnel, r.Dst)
		}
	}
	var podMainSpecific []netip.Prefix // non-default routes the primary CNI installed
	podMainSpecific = append(podMainSpecific, in.Cluster.PodCIDRs...)
	podMainSpecific = append(podMainSpecific, primaryRoutes...)
	var connected []netip.Prefix
	for _, a := range p.Addresses {
		connected = append(connected, a.Masked())
	}
	enabled := func(a netip.Addr) bool { return a.Is4() || !in.IPv6Disabled }
	unmarked := uint32(0)
	fail := func(prop string, dst netip.Addr, mark uint32, got string) {
		t.Helper()
		t.Fatalf("property %s violated for dst %s (mark %#x): routed to %s\nrules: %+v\nroutes: %+v",
			prop, dst, mark, got, p.Rules, p.Routes)
	}

	for _, dst := range probes(rng, in, p) {
		if !enabled(dst) {
			continue
		}
		// 1. Carve-outs always use the uplink.
		if inAny(dst, carveOuts) {
			for _, mark := range []uint32{unmarked, p.Device.FwMark} {
				if got := up.Lookup(dst, mark); got != uplink {
					fail("1 (carve-out uses uplink)", dst, mark, got)
				}
			}
			continue
		}
		// 6. The primary CNI's own specific routes win. (Connected routes of
		// the plan's addresses are more specific still, so skip those.)
		if inAny(dst, primaryRoutes) && !inAny(dst, connected) {
			if got := up.Lookup(dst, unmarked); got != uplink {
				fail("6 (primary CNI routes win)", dst, unmarked, got)
			}
			continue
		}
		inTunnel := inAny(dst, tunnel) && !inAny(dst, podMainSpecific)
		// 3. Tunnel destinations enter the tunnel.
		if inTunnel {
			if got := up.Lookup(dst, unmarked); got != p.Link.Name && !inAny(dst, connected) {
				fail("3 (AllowedIPs enter the tunnel)", dst, unmarked, got)
			}
			// 4. Kill switch.
			if got := down.Lookup(dst, unmarked); got == uplink {
				fail("4 (kill switch)", dst, unmarked, got)
			}
		}
		// 5. Unclaimed destinations are left alone.
		if !inAny(dst, tunnel) && !inAny(dst, connected) {
			if got := up.Lookup(dst, unmarked); got != uplink {
				fail("5 (unclaimed traffic untouched)", dst, unmarked, got)
			}
		}
	}
	// 2. No loops: the socket's own packets reach every endpoint via the uplink.
	if p.Mode == ModePod {
		for _, peer := range p.Device.Peers {
			if peer.Endpoint == nil {
				continue
			}
			dst := peer.Endpoint.Addr()
			if got := up.Lookup(dst, p.Device.FwMark); got != uplink {
				fail("2 (no tunnel loop)", dst, p.Device.FwMark, got)
			}
			// 7. The reverse-path check of a reply from the endpoint to the
			// socket: unmarked, UDP, to our listen port.
			if dst.Is4() {
				flow := routesim.Flow{Dst: dst, Proto: ProtoUDP, SPort: uint16(p.Device.ListenPort)} // #nosec G115
				if got := up.LookupFlow(flow); got != uplink {
					fail("7 (replies pass strict rp_filter)", dst, 0, got)
				}
			}
		}
	}
}

// randomInput generates a plausible config and environment. Roughly half are
// invalid in some way; those are skipped by the caller, but still exercise
// Compute's error paths.
func randomInput(rng *rand.Rand) Input {
	pick := func(opts ...string) string { return opts[rng.IntN(len(opts))] }
	v4 := func(bitsMin, bitsMax int) netip.Prefix {
		var b [4]byte
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), bitsMin+rng.IntN(bitsMax-bitsMin+1)).Masked()
	}
	v6 := func(bitsMin, bitsMax int) netip.Prefix {
		var b [16]byte
		b[0] = 0xfd
		for i := 1; i < len(b); i++ {
			b[i] = byte(rng.IntN(256))
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), bitsMin+rng.IntN(bitsMax-bitsMin+1)).Masked()
	}

	in := Input{
		Mode:         Mode(pick(string(ModePod), string(ModeHost))),
		ContainerID:  "c0ffee",
		IPv6Disabled: rng.IntN(3) == 0,
		UplinkMTU:    []int{0, 1450, 1500, 9001}[rng.IntN(4)],
		Resolved:     map[string]netip.Addr{},
		Cluster: ClusterInfo{
			PodCIDRs:     []netip.Prefix{v4(8, 20)},
			ServiceCIDRs: []netip.Prefix{v4(12, 24)},
			NodeIPs:      []netip.Addr{v4(32, 32).Addr()},
		},
	}
	if rng.IntN(2) == 0 {
		in.Cluster.PodCIDRs = append(in.Cluster.PodCIDRs, v6(48, 64))
		in.Cluster.ServiceCIDRs = append(in.Cluster.ServiceCIDRs, v6(104, 120))
	}
	if rng.IntN(4) == 0 {
		in.Cluster.ExtraExcludes = []netip.Prefix{netip.MustParsePrefix("169.254.20.10/32")}
	}

	var conf strings.Builder
	fmt.Fprintf(&conf, "[Interface]\nPrivateKey = %s\n", testIfaceKey)
	var subnets []netip.Prefix // address subnets, to aim some endpoints into
	for range 1 + rng.IntN(2) {
		p := v4(16, 32)
		if rng.IntN(2) == 1 {
			p = v6(64, 128)
		}
		subnets = append(subnets, p)
		fmt.Fprintf(&conf, "Address = %s/%d\n", routesim.RandomIn(rng, p), p.Bits())
	}
	peerKeys := []string{testPeer1Key, "OyE87QA+ibNaJsIsvQEcm/qylXhBWyBp9/yLAZmLkD0=", "5Cu/hTP08LHUTn/ByaxUpqw2hkLdG4oQoXdSVe7Qwxo="}
	for i := range 1 + rng.IntN(len(peerKeys)) {
		fmt.Fprintf(&conf, "[Peer]\nPublicKey = %s\n", peerKeys[i])
		var allowed []string
		for range rng.IntN(4) {
			switch rng.IntN(6) {
			case 0:
				allowed = append(allowed, "0.0.0.0/0")
			case 1:
				allowed = append(allowed, "::/0")
			case 2, 3:
				allowed = append(allowed, v4(1, 32).String())
			case 4:
				allowed = append(allowed, v6(1, 128).String())
			case 5: // deliberately overlap a cluster range
				allowed = append(allowed, in.Cluster.ServiceCIDRs[0].String())
			}
		}
		if len(allowed) > 0 {
			fmt.Fprintf(&conf, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
		}
		switch rng.IntN(5) {
		case 3: // inside our own subnet: Compute must reject it (would loop)
			a := routesim.RandomIn(rng, subnets[rng.IntN(len(subnets))])
			fmt.Fprintf(&conf, "Endpoint = %s\n", netip.AddrPortFrom(a, 51820))
		case 0:
			fmt.Fprintf(&conf, "Endpoint = %s:51820\n", v4(32, 32).Addr())
		case 1:
			fmt.Fprintf(&conf, "Endpoint = [%s]:51820\n", v6(128, 128).Addr())
		case 2:
			host := fmt.Sprintf("peer%d.example.com", i)
			in.Resolved[host] = v4(32, 32).Addr()
			fmt.Fprintf(&conf, "Endpoint = %s:51820\n", host)
		}
	}
	cfg, err := wgconfig.Parse([]byte(conf.String()))
	if err != nil {
		return Input{} // e.g. two peers claiming the same AllowedIPs
	}
	in.Config = cfg
	return in
}

// TestRandomizedInvariants checks the routing properties on random inputs.
// The seed is fixed so failures reproduce; raise -count or change the seed
// locally to explore further.
func TestRandomizedInvariants(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x20261108, 0xca6c))
	const n = 5000
	computed := 0
	for i := range n {
		in := randomInput(rng)
		if in.Config == nil {
			continue
		}
		p, err := Compute(in)
		if err != nil {
			continue
		}
		computed++
		t.Run(fmt.Sprint(i), func(t *testing.T) { checkInvariants(t, in, p) })
		if t.Failed() {
			t.Logf("failing config:\n%s\ninput: %+v", wgconfig.Encode(in.Config), in)
			return
		}
	}
	// Guard against the generator degrading into producing only errors.
	if computed < n/3 {
		t.Fatalf("only %d of %d random inputs produced a plan", computed, n)
	}
	t.Logf("%d of %d random inputs produced a plan", computed, n)
}

// TestSimulatorAgreesWithWgQuickExample sanity-checks the simulator itself
// on a hand-worked example, so a bug in the model can't hide a bug in Compute.
func TestSimulatorAgreesWithWgQuickExample(t *testing.T) {
	cfg := mustParse(t, "[Interface]\nPrivateKey = "+testIfaceKey+"\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = "+
		testPeer1Key+"\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.20:51820\n")
	in := Input{Config: cfg, Cluster: ClusterInfo{
		PodCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16")},
		ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")},
	}}
	p, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	up, down := newSim(in, p, true), newSim(in, p, false)
	cases := []struct {
		sim  *routesim.Netns
		dst  string
		mark uint32
		want string
	}{
		{up, "1.1.1.1", 0, "wg0"},
		{up, "198.51.100.20", DefaultFwMark, "eth0"}, // the encrypted packets
		{up, "198.51.100.20", 0, "wg0"},              // app traffic to the same IP is tunnelled
		{up, "10.96.0.10", 0, "eth0"},                // kube-dns Service
		{up, "10.244.1.7", 0, "eth0"},                // another pod
		{down, "1.1.1.1", 0, routesim.Blackhole},
		{down, "10.96.0.10", 0, "eth0"},
	}
	for _, c := range cases {
		if got := c.sim.Lookup(netip.MustParseAddr(c.dst), c.mark); got != c.want {
			t.Errorf("route(%s, mark %#x) = %s, want %s", c.dst, c.mark, got, c.want)
		}
	}
}
