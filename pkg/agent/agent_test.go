package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/install"
	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/resolver"
)

const (
	ifaceKey = "KZKC22QUVCRS52irjCHVv2MX/QI/lHAsVKW1m1J/s9U="
	peerKey  = "aYdQoJuTQzd0bwlzRIFn82TK4TLi+LMnrkkT5bVEUCk="
	conflist = "10-flannel.conflist"
)

type node struct {
	t        *testing.T
	agent    *Agent
	client   *fake.Clientset
	confDir  string
	binDir   string
	socket   string
	original []byte
	cancel   context.CancelFunc
	done     chan error
}

// start runs an agent against a temp "node": CNI dirs, a socket and a fake
// API server holding the node, an annotated pod, its Secret and the agent's
// DaemonSet.
func start(t *testing.T, withPrimary bool) *node {
	t.Helper()
	dir := t.TempDir()
	n := &node{
		t: t, confDir: filepath.Join(dir, "net.d"), binDir: filepath.Join(dir, "bin"),
		socket: filepath.Join(dir, "run", "zora.sock"), done: make(chan error, 1),
	}
	var err error
	if n.original, err = os.ReadFile("../install/testdata/primaries/flannel.conflist"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(n.confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if withPrimary {
		n.writePrimary()
	}
	src := filepath.Join(dir, "zora-cni")
	if err := os.WriteFile(src, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wg := "[Interface]\nPrivateKey = " + ifaceKey + "\nAddress = 100.64.0.2/32\n[Peer]\nPublicKey = " + peerKey +
		"\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.7:51820\n"
	n.client = fake.NewClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "172.18.0.2"}, {Type: corev1.NodeHostName, Address: "node-1"},
		}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "172.18.0.3"},
		}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "vpn", UID: "uid-vpn",
			Annotations: map[string]string{agentapi.AnnotationSecret: "wg"}}, Spec: corev1.PodSpec{NodeName: "node-1"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "wg"},
			Data: map[string][]byte{agentapi.DefaultSecretKey: []byte(wg)}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "zora-system", Name: "zora-agent"}},
	)
	n.agent, err = New(Options{
		NodeName: "node-1", Socket: n.socket, CNIConfDir: n.confDir, CNIBinDir: n.binDir, PluginSource: src,
		Cluster: plan.ClusterInfo{
			PodCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16")},
			ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")},
		},
		Resync: 50 * time.Millisecond, RepairInterval: 50 * time.Millisecond,
		DaemonSetNamespace: "zora-system", DaemonSetName: "zora-agent",
	}, n.client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	go func() { n.done <- n.agent.Run(ctx) }()
	t.Cleanup(func() { _ = n.stop() })
	return n
}

func (n *node) writePrimary() {
	n.t.Helper()
	if err := os.WriteFile(filepath.Join(n.confDir, conflist), n.original, 0o644); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) stop() error {
	n.cancel()
	select {
	case err := <-n.done:
		n.done <- err // allow a second stop (from Cleanup)
		return err
	case <-time.After(15 * time.Second):
		n.t.Fatal("agent did not stop")
		return nil
	}
}

func (n *node) waitReady() {
	n.t.Helper()
	var err error
	for range 400 {
		if err = n.agent.Ready(); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	n.t.Fatalf("agent never became ready: %v", err)
}

func (n *node) chained() bool {
	b, err := os.ReadFile(filepath.Join(n.confDir, conflist))
	return err == nil && install.HasEntry(conflist, b)
}

func (n *node) binaryInstalled() bool {
	_, err := os.Stat(filepath.Join(n.binDir, "zora"))
	return err == nil
}

func TestAgentServesAndStaysInstalledAcrossRestarts(t *testing.T) {
	n := start(t, true)
	n.waitReady()
	if !n.chained() || !n.binaryInstalled() {
		t.Fatalf("chained = %v, binary = %v", n.chained(), n.binaryInstalled())
	}
	b, _ := os.ReadFile(filepath.Join(n.confDir, conflist))
	if !strings.Contains(string(b), n.socket) {
		t.Fatalf("the conflist entry does not point at the agent's socket:\n%s", b)
	}

	// The plugin's view: ask over the real socket.
	c := agentapi.NewClient(n.socket, 5*time.Second)
	ctx := context.Background()
	if err := c.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
	ref := agentapi.Pod{Namespace: "apps", Name: "vpn", UID: "uid-vpn"}
	resp, err := c.Resolve(ctx, agentapi.ResolveRequest{Pod: ref, ContainerID: "c1"})
	if err != nil || resp.Action != agentapi.ActionConfigure {
		t.Fatalf("resolve: %+v, %v", resp, err)
	}
	// Every node's address stays out of the tunnel, not only this node's:
	// on a real cluster, a Service backed by host-network pods on other
	// nodes (the API server) was unreachable from a tunnelled pod.
	carved := map[string]bool{}
	for _, r := range resp.Plan.Rules {
		if r.Dst != nil {
			carved[r.Dst.String()] = true
		}
	}
	if !carved["172.18.0.2/32"] || !carved["172.18.0.3/32"] {
		t.Errorf("node addresses are not kept out of the tunnel: carve-outs = %v", carved)
	}
	if err := c.Report(ctx, agentapi.ReportRequest{Pod: ref, ContainerID: "c1", OK: true}); err != nil {
		t.Fatal(err)
	}
	if p, _ := n.client.CoreV1().Pods("apps").Get(ctx, "vpn", metav1.GetOptions{}); !resolver.IsReady(p) {
		t.Errorf("pod conditions = %+v", p.Status.Conditions)
	}

	// The primary CNI rewrites its config; the agent chains itself back in.
	n.writePrimary()
	for i := 0; !n.chained(); i++ {
		if i > 400 {
			t.Fatal("not re-chained after the primary rewrote its config")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// A restart (rolling update, node drain): the DaemonSet still exists,
	// so the node keeps its plugin.
	if err := n.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !n.chained() || !n.binaryInstalled() {
		t.Fatalf("after a restart: chained = %v, binary = %v; both must stay", n.chained(), n.binaryInstalled())
	}
}

func TestAgentWaitsForThePrimary(t *testing.T) {
	n := start(t, false)
	time.Sleep(300 * time.Millisecond)
	if err := n.agent.Ready(); err == nil || !strings.Contains(err.Error(), "not chained") {
		t.Fatalf("Ready() = %v with no primary CNI config", err)
	}
	entries, _ := os.ReadDir(n.confDir)
	if len(entries) != 0 {
		t.Fatalf("the agent wrote %v into an empty CNI config dir", entries)
	}
	n.writePrimary()
	n.waitReady()
	if !n.chained() {
		t.Fatal("not chained after the primary arrived")
	}
}

func TestAgentUninstallsWhenItsDaemonSetIsDeleted(t *testing.T) {
	n := start(t, true)
	n.waitReady()
	if err := n.client.AppsV1().DaemonSets("zora-system").Delete(context.Background(), "zora-agent", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := n.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n.chained() || n.binaryInstalled() {
		t.Fatalf("after uninstall: chained = %v, binary = %v", n.chained(), n.binaryInstalled())
	}
	got, _ := os.ReadFile(filepath.Join(n.confDir, conflist))
	wantName, want, err := install.Chain(conflist, n.original, []byte(`{"type":"zora"}`))
	if err != nil || wantName != conflist {
		t.Fatal(err)
	}
	want, _, _ = install.Unchain(conflist, want)
	if string(got) != string(want) {
		t.Fatalf("the primary's config was not restored:\n%s", got)
	}
}

// TestAgentUninstallsWhenItsPermissionsAreRevoked: helm uninstall and
// namespace deletion remove the RBAC alongside the DaemonSet. An agent that
// can no longer ask must not leave the plugin chained in with no agent.
func TestAgentUninstallsWhenItsPermissionsAreRevoked(t *testing.T) {
	for name, err := range map[string]error{
		"forbidden":    apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "daemonsets"}, "zora-agent", errors.New("RBAC")),
		"unauthorized": apierrors.NewUnauthorized("token revoked"),
	} {
		t.Run(name, func(t *testing.T) {
			n := start(t, true)
			n.waitReady()
			n.client.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, err
			})
			if err := n.stop(); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if n.chained() || n.binaryInstalled() {
				t.Fatalf("chained = %v, binary = %v; both must be removed", n.chained(), n.binaryInstalled())
			}
		})
	}
}

func TestAgentStaysInstalledWhenTheAPIServerIsUnreachable(t *testing.T) {
	n := start(t, true)
	n.waitReady()
	n.client.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("dial tcp 10.96.0.1:443: i/o timeout")
	})
	if err := n.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !n.chained() || !n.binaryInstalled() {
		t.Fatalf("chained = %v, binary = %v; a node that merely lost the API server must keep zora", n.chained(), n.binaryInstalled())
	}
}

func TestRemoveDaemonSet(t *testing.T) {
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "zora-system", Name: "zora-agent"}}
	client := fake.NewClientset(ds)
	// Model foreground deletion: the DaemonSet lingers while its pods
	// terminate, then disappears.
	gets := 0
	client.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		if gets++; gets <= 3 {
			return true, ds, nil
		}
		return false, nil, nil
	})
	var policy *metav1.DeletionPropagation
	client.PrependReactor("delete", "daemonsets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		policy = a.(k8stesting.DeleteAction).GetDeleteOptions().PropagationPolicy
		return false, nil, nil
	})
	if err := RemoveDaemonSet(context.Background(), client, "zora-system", "zora-agent", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if gets < 4 {
		t.Fatalf("returned after %d checks, before the DaemonSet was gone", gets)
	}
	if policy == nil || *policy != metav1.DeletePropagationForeground {
		t.Fatalf("propagation policy = %v, want foreground so the wait covers the pods", policy)
	}
	// Already gone (a retried hook): succeed.
	if err := RemoveDaemonSet(context.Background(), client, "zora-system", "zora-agent", time.Millisecond); err != nil {
		t.Fatalf("second call: %v", err)
	}
	// Pods that never finish: give up with an explanation.
	stuck := fake.NewClientset(ds)
	stuck.PrependReactor("delete", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := RemoveDaemonSet(ctx, stuck, "zora-system", "zora-agent", time.Millisecond); err == nil || !strings.Contains(err.Error(), "waiting for DaemonSet") {
		t.Fatalf("err = %v", err)
	}
}

func TestOptionsValidation(t *testing.T) {
	if _, err := New(Options{}, nil, nil); err == nil {
		t.Fatal("accepted options without a node name")
	}
	if _, err := New(Options{NodeName: "n"}, nil, nil); err == nil {
		t.Fatal("accepted options without CNI directories")
	}
}
