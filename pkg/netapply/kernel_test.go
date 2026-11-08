package netapply

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/tyler-lloyd/zora/internal/routesim"
	"github.com/tyler-lloyd/zora/internal/testns"
	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

// goldenCase is one of pkg/plan's golden inputs, so every routing scenario
// added there is automatically applied to a real kernel here.
type goldenCase struct {
	name string
	in   plan.Input
	plan *plan.Plan
}

func goldenCases(t *testing.T) []goldenCase {
	t.Helper()
	confs, _ := filepath.Glob("../plan/testdata/*/wg.conf")
	if len(confs) == 0 {
		t.Fatal("no golden cases found in ../plan/testdata")
	}
	var out []goldenCase
	for _, confPath := range confs {
		dir := filepath.Dir(confPath)
		conf, err := os.ReadFile(confPath)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "input.json"))
		if err != nil {
			t.Fatal(err)
		}
		var in plan.Input
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatal(err)
		}
		cfg, err := wgconfig.Parse(conf)
		if err != nil {
			t.Fatal(err)
		}
		in.Config = cfg
		p, err := plan.Compute(in)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, goldenCase{name: filepath.Base(dir), in: in, plan: p})
	}
	return out
}

// TestKernelAgreesWithModel applies every golden plan to a real namespace,
// then checks, for many destinations and fwmarks, that the kernel's routing
// decision ("ip route get") equals routesim's decision on the same tables
// and rules. pkg/plan proves its safety properties on routesim; this test is
// what makes those proofs hold for the kernel.
//
// It also checks Verify accepts what Apply built, and that Remove restores
// the namespace exactly.
func TestKernelAgreesWithModel(t *testing.T) {
	testns.RequireWireGuard(t)
	for _, gc := range goldenCases(t) {
		t.Run(gc.name, func(t *testing.T) {
			host, pod := testns.New(t, "host"), newPod(t)
			before, hostBefore := snapshot(t, pod), snapshot(t, host)
			opts := Options{HostNS: host.Path}
			if err := Apply(pod.Path, gc.plan, opts); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if err := Verify(pod.Path, gc.plan); err != nil {
				t.Fatalf("Verify: %v", err)
			}

			rng := rand.New(rand.NewPCG(7, 7))
			var prefixes []netip.Prefix
			prefixes = append(prefixes, gc.in.Cluster.PodCIDRs...)
			prefixes = append(prefixes, gc.in.Cluster.ServiceCIDRs...)
			prefixes = append(prefixes, gc.in.Cluster.ExtraExcludes...)
			prefixes = append(prefixes, gc.plan.Addresses...)
			for _, peer := range gc.plan.Device.Peers {
				prefixes = append(prefixes, peer.AllowedIPs...)
			}
			prefixes = append(prefixes,
				netip.MustParsePrefix("169.254.1.1/32"), netip.MustParsePrefix("fe80::/64"),
				netip.MustParsePrefix(podIP+"/24"), netip.MustParsePrefix(podIP6+"/64"))
			extra := gc.in.Cluster.NodeIPs
			for _, peer := range gc.plan.Device.Peers {
				if peer.Endpoint != nil {
					extra = append(extra, peer.Endpoint.Addr())
				}
			}
			probes := routesim.Probes(rng, prefixes, extra...)
			marks := []uint32{0, 0x1}
			if gc.plan.Device.FwMark != 0 {
				marks = append(marks, gc.plan.Device.FwMark)
			}

			compare := func(stage string) {
				t.Helper()
				model, local := modelFromKernel(t, pod)
				checked := 0
				for _, dst := range probes {
					if inLocalTable(local, dst) {
						continue // local/broadcast/multicast: not what we model
					}
					for _, mark := range marks {
						want := kernelLookup(t, pod, dst, mark)
						if got := model.Lookup(dst, mark); got != want {
							t.Errorf("%s: dst %s mark %#x: kernel routes to %s, model says %s", stage, dst, mark, want, got)
						}
						checked++
					}
				}
				if checked < 50 {
					t.Fatalf("%s: only %d decisions compared", stage, checked)
				}
			}
			compare("link up")
			// The kill switch is the other state that matters.
			pod.Must(t, pod.Handle.LinkDel(pod.Link(t, gc.plan.Link.Name)))
			compare("link deleted")
			if t.Failed() {
				t.Log(debugDump(pod))
			}

			if err := Remove(pod.Path, gc.plan, opts); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			assertSameState(t, "pod after Remove", before, snapshot(t, pod))
			assertSameState(t, "host after Remove", hostBefore, snapshot(t, host))
		})
	}
}

// modelFromKernel builds a routesim model from the namespace's actual routes
// and rules. It also returns the local table, which the model ignores.
func modelFromKernel(t *testing.T, ns *testns.NS) (*routesim.Netns, []netip.Prefix) {
	t.Helper()
	links, err := ns.Handle.LinkList()
	ns.Must(t, err)
	names := map[int]string{}
	for _, l := range links {
		names[l.Attrs().Index] = l.Attrs().Name
	}
	kroutes, err := ns.Handle.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	ns.Must(t, err)
	var routes []routesim.Route
	var local []netip.Prefix
	for _, r := range kroutes {
		dst := defaultPrefix(r.Family)
		if r.Dst != nil {
			dst = prefixOf(r.Dst)
		}
		if r.Table == unix.RT_TABLE_LOCAL {
			local = append(local, dst)
			continue
		}
		routes = append(routes, routesim.Route{
			Table: r.Table, Dst: dst, Dev: names[r.LinkIndex],
			Blackhole: r.Type == unix.RTN_BLACKHOLE, Metric: r.Priority,
		})
	}
	var rules []routesim.Rule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		krules, err := ns.Handle.RuleList(fam)
		ns.Must(t, err)
		for _, r := range krules {
			if r.Table == unix.RT_TABLE_LOCAL {
				continue
			}
			rr := routesim.Rule{Priority: r.Priority, IPv6: fam == netlink.FAMILY_V6, Mark: r.Mark, Invert: r.Invert, Table: r.Table, IPProto: uint8(r.IPProto)}
			if r.Dst != nil {
				d := prefixOf(r.Dst)
				rr.Dst = &d
			}
			if r.Sport != nil {
				rr.SPort = r.Sport.Start
			}
			if r.SuppressPrefixlen >= 0 {
				s := r.SuppressPrefixlen
				rr.SuppressPrefixLength = &s
			}
			rules = append(rules, rr)
		}
	}
	return routesim.New(routes, rules), local
}

func defaultPrefix(fam int) netip.Prefix {
	if fam == netlink.FAMILY_V6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

func inLocalTable(local []netip.Prefix, a netip.Addr) bool {
	for _, p := range local {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// kernelLookup asks the kernel how it would route a locally generated packet.
func kernelLookup(t *testing.T, ns *testns.NS, dst netip.Addr, mark uint32) string {
	t.Helper()
	routes, err := ns.Handle.RouteGetWithOptions(net.IP(dst.AsSlice()), &netlink.RouteGetOptions{Mark: mark})
	switch {
	case errors.Is(err, unix.EINVAL): // IPv4 blackhole
		return routesim.Blackhole
	case errors.Is(err, unix.ENETUNREACH):
		return routesim.Unreachable
	case err != nil:
		t.Fatalf("route get %s mark %#x: %v", dst, mark, err)
	}
	r := routes[0]
	switch r.Type {
	case unix.RTN_BLACKHOLE:
		return routesim.Blackhole
	case unix.RTN_UNREACHABLE:
		return routesim.Unreachable
	}
	l, err := ns.Handle.LinkByIndex(r.LinkIndex)
	ns.Must(t, err)
	return l.Attrs().Name
}
