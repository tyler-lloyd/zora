package integration

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/tyler-lloyd/zora/internal/testns"
	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/resolver"
)

type staticDNS map[string]netip.Addr

func (d staticDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := d[host]; ok {
		return []netip.Addr{a}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// TestPluginWithRealResolver is the whole path short of a cluster: an
// annotated Pod and a Secret in a (fake) API server, the real resolver
// behind the agent socket, the real plugin binary in a real CNI chain, and
// traffic through the resulting tunnel.
func TestPluginWithRealResolver(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// The Secret names the peer by host name, as a user's would.
	conf, tunIP := w.tunnelConf(t, "vpn.example.com")
	pod := func(name, id, secret string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: name, UID: types.UID("uid-" + id),
			Annotations: map[string]string{agentapi.AnnotationSecret: secret},
		}}
	}
	good, broken := pod("vpn", "r0001", "wg"), pod("typo", "r0002", "wgg")
	client := fake.NewClientset(good, broken, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wg"},
		Data:       map[string][]byte{agentapi.DefaultSecretKey: []byte(conf)},
	})
	events := record.NewFakeRecorder(20)
	res := &resolver.Resolver{
		Client: client, Events: events,
		// An empty cache: sandboxes are usually created before the
		// informer has seen the pod.
		Pods:   corelisters.NewPodLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})),
		DNS:    staticDNS{"vpn.example.com": netip.MustParseAddr(peerIP)},
		Config: resolver.Config{Cluster: clusterInfo()},
	}
	socket := filepath.Join(t.TempDir(), "zora.sock")
	l, err := agentapi.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := agentapi.NewServer(res)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	list := w.conflist(t, conflistOpts{version: "0.3.1", primary: "bridge", socket: socket, withZora: true})

	t.Run("annotated pod gets a working tunnel", func(t *testing.T) {
		ns := testns.New(t, "pod")
		rt := runtimeConf(ns, "apps", "vpn", "r0001")
		if _, err := w.cni.AddNetworkList(ctx, list, rt); err != nil {
			t.Fatalf("ADD: %v", err)
		}
		testns.MustWhoami(t, ns, net.JoinHostPort(inetIP, "8080"), "", tunIP, "traffic through the tunnel")
		got, err := client.CoreV1().Pods("apps").Get(ctx, "vpn", metav1.GetOptions{})
		if err != nil || !resolver.IsReady(got) {
			t.Fatalf("pod condition %s not set: %+v (%v)", agentapi.ReadyCondition, got.Status.Conditions, err)
		}
		if err := w.cni.DelNetworkList(ctx, list, rt); err != nil {
			t.Fatalf("DEL: %v", err)
		}
	})

	t.Run("a bad annotation fails the pod with an explanation", func(t *testing.T) {
		ns := testns.New(t, "pod")
		rt := runtimeConf(ns, "apps", "typo", "r0002")
		const want = `secret "wgg" (annotation zora.io/wireguard-secret) not found`
		_, err := w.cni.AddNetworkList(ctx, list, rt)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("ADD = %v; the runtime must see why", err)
		}
		found := false
		for len(events.Events) > 0 {
			if ev := <-events.Events; strings.Contains(ev, want) {
				found = true
			}
		}
		if !found {
			t.Error("no Event on the pod explains the failure")
		}
		if err := w.cni.DelNetworkList(ctx, list, rt); err != nil {
			t.Fatalf("DEL: %v", err)
		}
	})
}
