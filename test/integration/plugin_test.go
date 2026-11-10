package integration

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/tyler-lloyd/zora/internal/testns"
	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

// TestPlugin shares one world (node, peer, agent) across its subtests.
func TestPlugin(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	inet := net.JoinHostPort(inetIP, "8080")
	n := 0
	newID := func() string { n++; return fmt.Sprintf("c%04d", n) }

	// The full lifecycle, for each primary plugin and spec version.
	for _, primary := range []string{"bridge", "ptp"} {
		for _, ver := range cniVersions {
			t.Run(fmt.Sprintf("lifecycle/%s/%s", primary, ver), func(t *testing.T) {
				id := newID()
				name := "vpn-" + id
				pod := testns.New(t, "pod")
				p, tunIP := w.tunnelFor(t, plan.ModePod, id)
				w.agent.set(name, p)
				list := w.conflist(t, conflistOpts{version: ver, primary: primary, socket: w.socket, withZora: true})
				rt := runtimeConf(pod, "apps", name, id)

				res, err := w.cni.AddNetworkList(ctx, list, rt)
				if err != nil {
					t.Fatalf("ADD: %v", err)
				}
				if res.Version() != ver {
					t.Errorf("result version %s, want %s (the conflist's)", res.Version(), ver)
				}
				r := asCurrent(t, res)
				last := r.Interfaces[len(r.Interfaces)-1]
				if last.Name != "wg0" || last.Sandbox != pod.Path {
					t.Errorf("last interface = %+v, want wg0 in the pod", last)
				}
				if len(r.IPs) != 1 || !strings.HasPrefix(r.IPs[0].Address.IP.String(), "10.2") {
					t.Errorf("IPs = %v; want only the primary's address", r.IPs)
				}
				if rep, ok := w.agent.reportFor(name); !ok || !rep.OK {
					t.Errorf("agent report = %+v, %v", rep, ok)
				}

				err = w.cni.CheckNetworkList(ctx, list, rt)
				if strings.HasPrefix(ver, "0.3.") {
					// CHECK arrived in spec 0.4.0; runtimes don't send it for 0.3.x.
					if err == nil || !strings.Contains(err.Error(), "does not support the CHECK command") {
						t.Errorf("CHECK on %s = %v; libcni should refuse it", ver, err)
					}
				} else if err != nil {
					t.Errorf("CHECK: %v", err)
				}
				testns.MustWhoami(t, pod, inet, "", tunIP, "pod traffic goes through the tunnel")

				podIP := r.IPs[0].Address.IP.String()
				network := list.Name
				if !slices.Contains(w.allocatedIPs(t, network), podIP) {
					t.Fatalf("host-local has no allocation for %s", podIP)
				}
				for i := range 2 {
					if err := w.cni.DelNetworkList(ctx, list, rt); err != nil {
						t.Fatalf("DEL #%d: %v", i+1, err)
					}
				}
				if l := wireguardLinks(t, pod); len(l) != 0 {
					t.Errorf("WireGuard links left after DEL: %v", l)
				}
				if slices.Contains(w.allocatedIPs(t, network), podIP) {
					t.Errorf("DEL did not reach host-local: %s still allocated", podIP)
				}
			})
		}
	}

	t.Run("unannotated pod is untouched", func(t *testing.T) {
		withZora, without := testns.New(t, "pod-a"), testns.New(t, "pod-b")
		opts := conflistOpts{version: "1.0.0", primary: "bridge", socket: w.socket}
		ida, idb := newID(), newID()
		opts.withZora = true
		ra, err := w.cni.AddNetworkList(ctx, w.conflist(t, opts), runtimeConf(withZora, "apps", "plain-"+ida, ida))
		if err != nil {
			t.Fatal(err)
		}
		opts.withZora = false
		rb, err := w.cni.AddNetworkList(ctx, w.conflist(t, opts), runtimeConf(without, "apps", "plain-"+idb, idb))
		if err != nil {
			t.Fatal(err)
		}
		a, b := asCurrent(t, ra), asCurrent(t, rb)
		if len(a.Interfaces) != len(b.Interfaces) || len(a.IPs) != len(b.IPs) || len(a.Routes) != len(b.Routes) {
			t.Errorf("results differ in shape:\nwith zora:    %v\nwithout zora: %v", a, b)
		}
		if l := wireguardLinks(t, withZora); len(l) != 0 {
			t.Errorf("unannotated pod got WireGuard links %v", l)
		}
		rules, err := withZora.Handle.RuleList(netlink.FAMILY_V4)
		withZora.Must(t, err)
		if len(rules) != 3 { // local, main, default
			t.Errorf("unannotated pod has extra rules: %v", rules)
		}
	})

	t.Run("agent down fails closed but DEL still works", func(t *testing.T) {
		pod := testns.New(t, "pod")
		id := newID()
		list := w.conflist(t, conflistOpts{version: "1.0.0", primary: "bridge", socket: "/nonexistent/zora.sock", withZora: true})
		rt := runtimeConf(pod, "apps", "orphan-"+id, id)
		_, err := w.cni.AddNetworkList(ctx, list, rt)
		if err == nil || !strings.Contains(err.Error(), "zora agent unreachable") {
			t.Fatalf("ADD = %v; want it to fail because the agent is unreachable", err)
		}
		before := len(w.allocatedIPs(t, list.Name))
		// The runtime cleans up a failed ADD with DEL, which must succeed
		// without the agent and release the primary's IP.
		if err := w.cni.DelNetworkList(ctx, list, rt); err != nil {
			t.Fatalf("DEL with the agent down: %v", err)
		}
		if after := len(w.allocatedIPs(t, list.Name)); after != before-1 {
			t.Errorf("allocations %d -> %d; DEL should release the failed pod's IP", before, after)
		}
	})

	t.Run("excluded namespace works with the agent down", func(t *testing.T) {
		pod := testns.New(t, "pod")
		id := newID()
		list := w.conflist(t, conflistOpts{version: "1.0.0", primary: "bridge", socket: "/nonexistent/zora.sock", withZora: true})
		rt := runtimeConf(pod, "kube-system", "coredns-"+id, id)
		if _, err := w.cni.AddNetworkList(ctx, list, rt); err != nil {
			t.Fatalf("kube-system pod blocked by a missing agent: %v", err)
		}
		_ = w.cni.DelNetworkList(ctx, list, rt)
	})

	t.Run("pod annotations from the runtime skip the agent", func(t *testing.T) {
		list := w.conflist(t, conflistOpts{version: "1.0.0", primary: "bridge", socket: "/nonexistent/zora.sock", withZora: true, capabilities: true})
		for _, c := range []struct {
			annotations map[string]string
			wantErr     bool
		}{
			{map[string]string{"team": "a"}, false},                     // not opted in: no agent needed
			{map[string]string{agentapi.AnnotationSecret: "vpn"}, true}, // opted in: needs the agent
		} {
			pod := testns.New(t, "pod")
			id := newID()
			rt := runtimeConf(pod, "apps", "anno-"+id, id)
			rt.CapabilityArgs = map[string]any{"io.kubernetes.cri.pod-annotations": c.annotations}
			_, err := w.cni.AddNetworkList(ctx, list, rt)
			if (err != nil) != c.wantErr {
				t.Errorf("annotations %v: ADD error %v, want error %v", c.annotations, err, c.wantErr)
			}
			_ = w.cni.DelNetworkList(ctx, list, rt)
		}
	})

	t.Run("apply failure fails ADD and leaves nothing behind", func(t *testing.T) {
		pod := testns.New(t, "pod")
		id := newID()
		name := "broken-" + id
		p, _ := w.tunnelFor(t, plan.ModePod, id)
		p.Sysctls = append(p.Sysctls, plan.Sysctl{Key: "kernel.panic", Value: "1"}) // the applier refuses non-net keys
		w.agent.set(name, p)
		list := w.conflist(t, conflistOpts{version: "1.0.0", primary: "bridge", socket: w.socket, withZora: true})
		rt := runtimeConf(pod, "apps", name, id)
		if _, err := w.cni.AddNetworkList(ctx, list, rt); err == nil || !strings.Contains(err.Error(), "refusing sysctl") {
			t.Fatalf("ADD = %v; want the applier's refusal", err)
		}
		if rep, ok := w.agent.reportFor(name); !ok || rep.OK || !strings.Contains(rep.Error, "refusing sysctl") {
			t.Errorf("agent report = %+v", rep)
		}
		if l := wireguardLinks(t, pod); len(l) != 0 {
			t.Errorf("failed ADD left WireGuard links: %v", l)
		}
		if err := w.cni.DelNetworkList(ctx, list, rt); err != nil {
			t.Errorf("DEL: %v", err)
		}
	})

	t.Run("host mode", func(t *testing.T) {
		pod := testns.New(t, "pod")
		id := newID()
		name := "hostmode-" + id
		p, tunIP := w.tunnelFor(t, plan.ModeHost, id)
		w.agent.set(name, p)
		list := w.conflist(t, conflistOpts{version: "1.1.0", primary: "ptp", socket: w.socket, withZora: true})
		rt := runtimeConf(pod, "apps", name, id)
		if _, err := w.cni.AddNetworkList(ctx, list, rt); err != nil {
			t.Fatalf("ADD: %v", err)
		}
		testns.MustWhoami(t, pod, inet, "", tunIP, "host-mode tunnel")
		// The socket stayed on the node: the peer saw the node's address.
		var ep string
		w.peer.Do(t, func() error {
			c, err := wgctrl.New()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			dev, err := c.Device("wg0")
			if err != nil {
				return err
			}
			for _, pe := range dev.Peers {
				if pe.Endpoint != nil && pe.PublicKey.String() == p.Device.PrivateKey.PublicKey().String() {
					ep = pe.Endpoint.IP.String()
				}
			}
			return nil
		})
		if ep != hostIP {
			t.Errorf("peer saw the pod's packets from %q, want the node %s", ep, hostIP)
		}
		if err := w.cni.DelNetworkList(ctx, list, rt); err != nil {
			t.Fatal(err)
		}
		if l := wireguardLinks(t, w.host); len(l) != 0 {
			t.Errorf("host-side links left after DEL: %v", l)
		}
	})

	t.Run("GC deletes orphaned host-side links", func(t *testing.T) {
		liveID := "live-" + newID()
		live, dead := plan.BirthName(liveID), plan.BirthName("dead-"+newID())
		for _, name := range []string{live, dead} {
			w.host.Must(t, w.host.Handle.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}))
		}
		t.Cleanup(func() { _ = w.host.Handle.LinkDel(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: live}}) })
		list := w.conflist(t, conflistOpts{version: "1.1.0", primary: "bridge", socket: w.socket, withZora: true})
		args := &libcni.GCArgs{ValidAttachments: []types.GCAttachment{{ContainerID: liveID, IfName: "eth0"}}}
		if err := w.cni.GCNetworkList(ctx, list, args); err != nil {
			t.Fatalf("GC: %v", err)
		}
		got := wireguardLinks(t, w.host)
		if slices.Contains(got, dead) || !slices.Contains(got, live) {
			t.Errorf("after GC host has %v; want %s kept and %s deleted", got, live, dead)
		}
	})

	t.Run("STATUS reflects the agent", func(t *testing.T) {
		up := w.conflist(t, conflistOpts{version: "1.1.0", primary: "bridge", socket: w.socket, withZora: true})
		if err := w.cni.GetStatusNetworkList(ctx, up); err != nil {
			t.Errorf("STATUS with the agent up: %v", err)
		}
		down := w.conflist(t, conflistOpts{version: "1.1.0", primary: "bridge", socket: "/nonexistent/zora.sock", withZora: true})
		if err := w.cni.GetStatusNetworkList(ctx, down); err == nil || !strings.Contains(err.Error(), "zora agent is not ready") {
			t.Errorf("STATUS with the agent down = %v", err)
		}
	})
}
