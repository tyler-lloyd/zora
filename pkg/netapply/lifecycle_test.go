package netapply

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tyler-lloyd/zora/internal/testns"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

func lifecyclePlan(t *testing.T, mode plan.Mode) *plan.Plan {
	t.Helper()
	return computePlan(t, fullTunnelConf(genKey(t), genKey(t).PublicKey()), plan.Input{
		Cluster: testCluster, Mode: mode, ContainerID: "lifecycle", UplinkMTU: 1500,
	})
}

var modes = []plan.Mode{plan.ModePod, plan.ModeHost}

// TestApplyRollsBackOnFailure injects a failure before every step and checks
// that Apply reports it and leaves both namespaces exactly as it found them.
func TestApplyRollsBackOnFailure(t *testing.T) {
	testns.RequireWireGuard(t)
	for _, mode := range modes {
		for _, failAt := range Steps {
			if mode == plan.ModePod && (failAt == StepBirth || failAt == StepMove) {
				continue
			}
			t.Run(string(mode)+"/"+failAt, func(t *testing.T) {
				host, pod := testns.New(t, "host"), newPod(t)
				p := lifecyclePlan(t, mode)
				before, hostBefore := snapshot(t, pod), snapshot(t, host)

				injected := errors.New("injected failure")
				failpoint = func(step string) error {
					if step == failAt {
						return injected
					}
					return nil
				}
				t.Cleanup(func() { failpoint = func(string) error { return nil } })

				err := Apply(pod.Path, p, Options{HostNS: host.Path})
				if !errors.Is(err, injected) || !strings.Contains(err.Error(), failAt) {
					t.Fatalf("Apply error = %v, want the injected failure at %s", err, failAt)
				}
				assertSameState(t, "pod after rollback", before, snapshot(t, pod))
				assertSameState(t, "host after rollback", hostBefore, snapshot(t, host))
			})
		}
	}
}

// TestApplyIsRetrySafe: the runtime retries ADD after failures; a second
// Apply over a complete first one must succeed and converge.
func TestApplyIsRetrySafe(t *testing.T) {
	testns.RequireWireGuard(t)
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			host, pod := testns.New(t, "host"), newPod(t)
			p := lifecyclePlan(t, mode)
			opts := Options{HostNS: host.Path}
			for i := range 3 {
				if err := Apply(pod.Path, p, opts); err != nil {
					t.Fatalf("Apply #%d: %v", i+1, err)
				}
			}
			if err := Verify(pod.Path, p); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestRemoveIsIdempotent covers CNI DEL's contract: it may be called
// repeatedly, before ADD, or after the namespace is gone.
func TestRemoveIsIdempotent(t *testing.T) {
	testns.RequireWireGuard(t)
	host, pod := testns.New(t, "host"), newPod(t)
	p := lifecyclePlan(t, plan.ModeHost)
	opts := Options{HostNS: host.Path}
	before := snapshot(t, pod)
	if err := Remove(pod.Path, p, opts); err != nil {
		t.Fatalf("Remove before Apply: %v", err)
	}
	assertSameState(t, "Remove before Apply", before, snapshot(t, pod))
	if err := Apply(pod.Path, p, opts); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := Remove(pod.Path, p, opts); err != nil {
			t.Fatalf("Remove #%d: %v", i+1, err)
		}
	}
	if err := Remove("/proc/self/fd/999999", p, opts); err != nil {
		t.Fatalf("Remove with a vanished netns: %v", err)
	}
}

// TestForeignInterfacesAreNeverTouched: if something else already owns the
// interface name, Apply refuses, and neither Apply's rollback nor Remove may
// delete it.
func TestForeignInterfacesAreNeverTouched(t *testing.T) {
	testns.RequireWireGuard(t)
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			host, pod := testns.New(t, "host"), newPod(t)
			p := lifecyclePlan(t, mode)
			pod.Dummy(t, p.Link.Name)
			if mode == plan.ModeHost {
				host.Dummy(t, p.Link.BirthName) // an unrelated link with our temp name
			}
			before, hostBefore := snapshot(t, pod), snapshot(t, host)
			opts := Options{HostNS: host.Path}
			err := Apply(pod.Path, p, opts)
			if err == nil {
				t.Fatal("Apply succeeded over an existing non-WireGuard interface")
			}
			if err := Remove(pod.Path, p, opts); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			assertSameState(t, "pod", before, snapshot(t, pod))
			assertSameState(t, "host", hostBefore, snapshot(t, host))
		})
	}
}

// TestVerifyDetectsDrift breaks one aspect of the applied state at a time
// and checks Verify notices, as CNI CHECK must.
func TestVerifyDetectsDrift(t *testing.T) {
	testns.RequireWireGuard(t)
	type drift struct {
		name  string
		apply func(t *testing.T, pod *testns.NS, p *plan.Plan)
		want  string
	}
	withWG := func(t *testing.T, pod *testns.NS, fn func(*wgctrl.Client) error) {
		pod.Do(t, func() error {
			wg, err := wgctrl.New()
			if err != nil {
				return err
			}
			defer func() { _ = wg.Close() }()
			return fn(wg)
		})
	}
	drifts := []drift{
		{"link deleted", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			pod.Must(t, pod.Handle.LinkDel(pod.Link(t, p.Link.Name)))
		}, "interface wg0"},
		{"link down", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			pod.Must(t, pod.Handle.LinkSetDown(pod.Link(t, p.Link.Name)))
		}, "is down"},
		{"mtu changed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			pod.Must(t, pod.Handle.LinkSetMTU(pod.Link(t, p.Link.Name), 1280))
		}, "MTU is 1280"},
		{"address removed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			pod.Must(t, pod.Handle.AddrDel(pod.Link(t, p.Link.Name), &netlink.Addr{IPNet: ipNet(p.Addresses[0])}))
		}, "address " + p0(t).Addresses[0].String()},
		{"tunnel route removed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			pod.Must(t, pod.Handle.RouteDel(toRoute(p.Routes[0], pod.Link(t, p.Link.Name).Attrs().Index)))
		}, "route unicast"},
		{"kill switch removed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			i := slices.IndexFunc(p.Routes, func(r plan.Route) bool { return r.Type == plan.RouteBlackhole })
			pod.Must(t, pod.Handle.RouteDel(toRoute(p.Routes[i], 0)))
		}, "route blackhole"},
		{"rule removed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			pod.Must(t, pod.Handle.RuleDel(toRule(p.Rules[len(p.Rules)-1])))
		}, "rule priority"},
		{"socket rule removed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			i := slices.IndexFunc(p.Rules, func(r plan.Rule) bool { return r.Priority == plan.PrioritySocket })
			pod.Must(t, pod.Handle.RuleDel(toRule(p.Rules[i])))
		}, "rule priority 31050"},
		{"sysctl reset", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			pod.Sysctl(t, "net.ipv4.conf.all.src_valid_mark", "0")
		}, "src_valid_mark"},
		{"private key changed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			k := genKey(t)
			withWG(t, pod, func(wg *wgctrl.Client) error { return wg.ConfigureDevice(p.Link.Name, wgtypes.Config{PrivateKey: &k}) })
		}, "private key"},
		{"fwmark changed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			m := 7
			withWG(t, pod, func(wg *wgctrl.Client) error {
				return wg.ConfigureDevice(p.Link.Name, wgtypes.Config{FirewallMark: &m})
			})
		}, "fwmark"},
		{"peer allowed IPs narrowed", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			withWG(t, pod, func(wg *wgctrl.Client) error {
				return wg.ConfigureDevice(p.Link.Name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
					PublicKey: wgtypes.Key(p.Device.Peers[0].PublicKey), ReplaceAllowedIPs: true,
					AllowedIPs: slices.Clone(nil2(ipNet(p.Addresses[0]))),
				}}})
			})
		}, "allowed IPs"},
		{"extra peer", func(t *testing.T, pod *testns.NS, p *plan.Plan) {
			withWG(t, pod, func(wg *wgctrl.Client) error {
				return wg.ConfigureDevice(p.Link.Name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: genKey(t).PublicKey()}}})
			})
		}, "2 peers"},
	}
	for _, d := range drifts {
		t.Run(d.name, func(t *testing.T) {
			host, pod := testns.New(t, "host"), newPod(t)
			p := lifecyclePlan(t, plan.ModePod)
			if err := Apply(pod.Path, p, Options{HostNS: host.Path}); err != nil {
				t.Fatal(err)
			}
			d.apply(t, pod, p)
			err := Verify(pod.Path, p)
			if err == nil || !strings.Contains(err.Error(), d.want) {
				t.Fatalf("Verify = %v, want an error mentioning %q", err, d.want)
			}
		})
	}
}

// p0 is a plan with the same shape as lifecyclePlan, for building expected
// messages before a subtest runs.
func p0(t *testing.T) *plan.Plan { return lifecyclePlan(t, plan.ModePod) }

func nil2[T any](v *T) []T { return []T{*v} }

func TestSysctlKeysAreValidated(t *testing.T) {
	for _, key := range []string{"kernel.core_pattern", "net..ipv4", "net/ipv4/x", "net.ipv4.conf.all.rp_filter/../../x", "NET.ipv4.x", ""} {
		if _, err := sysctlPath(key); err == nil {
			t.Errorf("sysctlPath(%q) accepted a key it must refuse", key)
		}
	}
	if p, err := sysctlPath("net.ipv4.conf.all.src_valid_mark"); err != nil || p != "/proc/sys/net/ipv4/conf/all/src_valid_mark" {
		t.Errorf("sysctlPath = %q, %v", p, err)
	}
}
