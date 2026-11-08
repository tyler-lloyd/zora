package netapply

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tyler-lloyd/zora/internal/testns"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

// world is a miniature cluster node plus the internet:
//
//	pod ──eth0/veth── host ──veth── peer
//	                  │             ├─ wg0: WireGuard server 10.200.0.1, fd00:200::1
//	                  │             └─ "internet" 203.0.113.1, 2001:db8:113::1
//	                  └─ Service IP 10.96.0.10, node IP 172.18.0.2
//
// The host can also reach 203.0.113.1 directly, so traffic that leaked out of
// the pod in the clear would still arrive; tests tell the paths apart by the
// source address the server sees.
type world struct {
	host, pod, peer *testns.NS
	podKey          wgtypes.Key
	peerKey         wgtypes.Key
}

// newWorld builds the topology. rpFilter is the pod's IPv4 reverse-path
// filtering mode: new namespaces inherit it from the host, and distributions
// differ (RHEL: 1 strict, systemd: 2 loose, kernel default: 0).
func newWorld(t *testing.T, rpFilter string) *world {
	t.Helper()
	testns.RequireWireGuard(t)
	w := &world{
		host: testns.New(t, "host"), pod: testns.New(t, "pod"), peer: testns.New(t, "peer"),
		podKey: genKey(t), peerKey: genKey(t),
	}
	host, pod, peer := w.host, w.pod, w.peer

	testns.Veth(t, host, "veth-pod", pod, "eth0")
	host.Addr(t, "veth-pod", podGW+"/24")
	host.Addr(t, "veth-pod", podGW6+"/64")
	configurePodUplink(t, pod)
	pod.Sysctl(t, "net.ipv4.conf.all.rp_filter", rpFilter)
	pod.Sysctl(t, "net.ipv4.conf.eth0.rp_filter", rpFilter)

	testns.Veth(t, host, "veth-peer", peer, "eth0")
	host.Addr(t, "veth-peer", hostIP+"/24")
	peer.Addr(t, "eth0", peerIP+"/24")
	peer.Route(t, "10.244.0.0/16", hostIP, "eth0")
	host.Sysctl(t, "net.ipv4.ip_forward", "1")

	host.Dummy(t, "svc")
	host.Addr(t, "svc", serviceIP+"/32")
	host.Addr(t, "svc", nodeIP+"/32")
	host.Route(t, inetIP+"/32", peerIP, "veth-peer") // the plaintext leak path

	peer.Dummy(t, "inet")
	peer.Addr(t, "inet", inetIP+"/32")
	peer.Addr(t, "inet", inetIP6+"/128")

	// The far end of the tunnel: a plain WireGuard server.
	peer.Must(t, peer.Handle.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg0"}}))
	peer.Addr(t, "wg0", "10.200.0.1/24")
	peer.Addr(t, "wg0", "fd00:200::1/64")
	port := 51820
	peer.Do(t, func() error {
		wg, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer func() { _ = wg.Close() }()
		return wg.ConfigureDevice("wg0", wgtypes.Config{
			PrivateKey: &w.peerKey, ListenPort: &port, ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{
				PublicKey: w.podKey.PublicKey(),
				AllowedIPs: []net.IPNet{
					*testns.IPNet(netip.MustParsePrefix(tunPodIP + "/32")),
					*testns.IPNet(netip.MustParsePrefix(tunPodIP6 + "/128")),
				},
			}},
		})
	})
	peer.Must(t, peer.Handle.LinkSetUp(peer.Link(t, "wg0")))

	serveWhoami(t, peer, ":8080")           // the internet server, both families
	serveWhoami(t, host, serviceIP+":8080") // a cluster Service
	serveWhoami(t, pod, ":9090")            // the app in the pod, for kubelet probes
	return w
}

// peerSeenEndpoint returns the source of the encrypted packets the peer
// received: where the pod's WireGuard socket lives.
func (w *world) peerSeenEndpoint(t *testing.T) string {
	t.Helper()
	var ep string
	w.peer.Do(t, func() error {
		wg, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer func() { _ = wg.Close() }()
		dev, err := wg.Device("wg0")
		if err != nil {
			return err
		}
		if len(dev.Peers) != 1 || dev.Peers[0].Endpoint == nil {
			return fmt.Errorf("peer has no endpoint for the pod: %+v", dev.Peers)
		}
		ep = dev.Peers[0].Endpoint.IP.String()
		return nil
	})
	return ep
}

func TestTunnelTraffic(t *testing.T) {
	cases := []struct {
		mode plan.Mode
		// where the peer sees encrypted packets come from
		wantEndpoint string
	}{
		// Pod mode: the socket is in the pod, so ciphertext leaves via eth0
		// and the primary CNI (here: routed, not NATed, by the host).
		{plan.ModePod, podIP},
		// Host mode: the socket stayed in the host netns.
		{plan.ModeHost, hostIP},
	}
	for _, c := range cases {
		for _, rp := range []string{"0", "1", "2"} {
			t.Run(fmt.Sprintf("%s/rp_filter=%s", c.mode, rp), func(t *testing.T) {
				w := newWorld(t, rp)
				inet := net.JoinHostPort(inetIP, "8080")
				inet6 := net.JoinHostPort(inetIP6, "8080")

				// Control: before zora, the leak path works, so the kill-switch
				// check below is meaningful.
				mustWhoami(t, w.pod, inet, "", podIP, "control (no tunnel)")
				before := snapshot(t, w.pod)
				hostBefore := snapshot(t, w.host)

				p := computePlan(t, fullTunnelConf(w.podKey, w.peerKey.PublicKey()), plan.Input{
					Cluster: testCluster, Mode: c.mode, ContainerID: "traffic-test", UplinkMTU: 1500,
				})
				opts := Options{HostNS: w.host.Path}
				if err := Apply(w.pod.Path, p, opts); err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if err := Verify(w.pod.Path, p); err != nil {
					t.Fatalf("Verify after Apply: %v", err)
				}

				mustWhoami(t, w.pod, inet, "", tunPodIP, "IPv4 internet traffic goes through the tunnel")
				mustWhoami(t, w.pod, inet6, "", tunPodIP6, "IPv6 internet traffic goes through the tunnel")
				mustWhoami(t, w.pod, net.JoinHostPort(serviceIP, "8080"), "", podIP, "Service traffic stays on eth0")
				mustWhoami(t, w.host, net.JoinHostPort(podIP, "9090"), nodeIP, nodeIP, "kubelet probes from the node IP get replies")
				if got := w.peerSeenEndpoint(t); got != c.wantEndpoint {
					t.Fatalf("peer saw encrypted packets from %s, want %s", got, c.wantEndpoint)
				}

				// Kill switch: remove the WireGuard link behind zora's back.
				w.pod.Must(t, w.pod.Handle.LinkDel(w.pod.Link(t, p.Link.Name)))
				mustNotConnect(t, w.pod, inet, "kill switch (IPv4)")
				mustNotConnect(t, w.pod, inet6, "kill switch (IPv6)")
				mustWhoami(t, w.pod, net.JoinHostPort(serviceIP, "8080"), "", podIP, "cluster traffic survives the tunnel going away")
				if err := Verify(w.pod.Path, p); err == nil {
					t.Fatal("Verify passed with the WireGuard link deleted")
				}

				if err := Remove(w.pod.Path, p, opts); err != nil {
					t.Fatalf("Remove: %v", err)
				}
				assertSameState(t, "pod after Remove", before, snapshot(t, w.pod))
				assertSameState(t, "host after Remove", hostBefore, snapshot(t, w.host))
				mustWhoami(t, w.pod, inet, "", podIP, "after Remove the pod is back to normal")
			})
		}
	}
}
