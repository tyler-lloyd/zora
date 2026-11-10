package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

// SHA-256 hashes of short strings, not real keys.
const (
	ifaceKey = "KZKC22QUVCRS52irjCHVv2MX/QI/lHAsVKW1m1J/s9U="
	peerKey  = "aYdQoJuTQzd0bwlzRIFn82TK4TLi+LMnrkkT5bVEUCk="
)

func conf(endpoint string) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 100.64.0.2/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s\n",
		ifaceKey, peerKey, endpoint)
}

func pod(name string, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: name, UID: types.UID("uid-" + name), Annotations: annotations,
	}}
}

func secret(name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name}, Data: map[string][]byte{}}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

type fakeDNS map[string][]string

func (d fakeDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addrs, ok := d[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

type env struct {
	*Resolver
	client *fake.Clientset
	events *record.FakeRecorder
	cache  cache.Indexer
}

// newEnv builds a resolver over a fake API server. Pods are in the API
// server; cached controls whether the informer cache has seen them yet.
func newEnv(t *testing.T, cached bool, objs ...runtime.Object) *env {
	t.Helper()
	idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if cached {
		for _, o := range objs {
			if p, ok := o.(*corev1.Pod); ok {
				if err := idx.Add(p); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	e := &env{client: fake.NewClientset(objs...), events: record.NewFakeRecorder(50), cache: idx}
	e.Resolver = &Resolver{
		Client: e.client, Pods: corelisters.NewPodLister(idx), Events: e.events,
		DNS: fakeDNS{"vpn.example.com": {"2001:db8::7", "203.0.113.7"}, "v6only.example.com": {"2001:db8::9"}},
		Config: Config{
			Cluster: plan.ClusterInfo{
				PodCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16")},
				ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")},
			},
			NodeIPs:            func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.18.0.2")} },
			HostModeNamespaces: []string{"trusted"},
		},
	}
	return e
}

func (e *env) drainEvents() []string {
	var out []string
	for {
		select {
		case ev := <-e.events.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func request(p *corev1.Pod) agentapi.ResolveRequest {
	return agentapi.ResolveRequest{
		Pod:         agentapi.Pod{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID)},
		ContainerID: "c1", UplinkMTU: 1450,
	}
}

func TestResolveSkipsUnannotatedPods(t *testing.T) {
	p := pod("plain", map[string]string{"team": "a"})
	e := newEnv(t, true, p)
	resp, err := e.Resolve(context.Background(), request(p))
	if err != nil || resp.Action != agentapi.ActionSkip || resp.Plan != nil {
		t.Fatalf("resp %+v, err %v", resp, err)
	}
	if ev := e.drainEvents(); len(ev) != 0 {
		t.Fatalf("events for an unannotated pod: %v", ev)
	}
	for _, a := range e.client.Actions() {
		if a.GetResource().Resource == "secrets" {
			t.Fatal("read a secret for an unannotated pod")
		}
	}
}

func TestResolveConfigures(t *testing.T) {
	p := pod("vpn", map[string]string{
		agentapi.AnnotationSecret: "wg", agentapi.AnnotationKey: "client.conf", agentapi.AnnotationIfName: "vpn0",
	})
	s := secret("wg", map[string]string{"client.conf": conf("vpn.example.com:51820"), "wg0.conf": "garbage"})
	for _, cached := range []bool{true, false} {
		t.Run(fmt.Sprintf("cached=%v", cached), func(t *testing.T) {
			// cached=false: the sandbox is created before the informer
			// has seen the pod, so the resolver must ask the API server.
			e := newEnv(t, cached, p, s)
			resp, err := e.Resolve(context.Background(), request(p))
			if err != nil || resp.Action != agentapi.ActionConfigure {
				t.Fatalf("resp %+v, err %v", resp, err)
			}
			pl, err := resp.Plan.Decode()
			if err != nil {
				t.Fatal(err)
			}
			if pl.Mode != plan.ModePod || pl.Link.Name != "vpn0" || pl.Link.MTU != 1450-plan.WireGuardOverhead {
				t.Errorf("plan link/mode = %+v / %s", pl.Link, pl.Mode)
			}
			// IPv4 is preferred when a name has both families.
			if ep := pl.Device.Peers[0].Endpoint; ep == nil || ep.String() != "203.0.113.7:51820" {
				t.Errorf("endpoint = %v, want the resolved IPv4 address", ep)
			}
			var carve []string
			for _, r := range pl.Rules {
				if r.Priority == plan.PriorityCarveOut {
					carve = append(carve, r.Dst.String())
				}
			}
			if got := strings.Join(carve, " "); got != "10.96.0.0/12 10.244.0.0/16 172.18.0.2/32" {
				t.Errorf("carve-outs = %s; want pod CIDR, service CIDR and node IP", got)
			}
		})
	}
}

func TestResolveIPv6OnlyEndpoint(t *testing.T) {
	p := pod("vpn", map[string]string{agentapi.AnnotationSecret: "wg"})
	e := newEnv(t, true, p, secret("wg", map[string]string{"wg0.conf": conf("v6only.example.com:51820")}))
	resp, err := e.Resolve(context.Background(), request(p))
	if err != nil {
		t.Fatal(err)
	}
	if ep := resp.Plan.Device.Peers[0].Endpoint; ep.String() != "[2001:db8::9]:51820" {
		t.Fatalf("endpoint = %v", ep)
	}
}

func TestResolveHostMode(t *testing.T) {
	ann := map[string]string{agentapi.AnnotationSecret: "wg", agentapi.AnnotationMode: ModeHost}
	s := secret("wg", map[string]string{"wg0.conf": conf("203.0.113.7:51820")})

	denied := pod("vpn", ann)
	e := newEnv(t, true, denied, s)
	_, err := e.Resolve(context.Background(), request(denied))
	if err == nil || !strings.Contains(err.Error(), `not allowed in namespace "apps"`) {
		t.Fatalf("host mode outside the allowlist: err = %v; it must be refused, not downgraded", err)
	}

	allowed := pod("vpn", ann)
	allowed.Namespace = "trusted"
	s2 := s.DeepCopy()
	s2.Namespace = "trusted"
	e = newEnv(t, true, allowed, s2)
	resp, err := e.Resolve(context.Background(), request(allowed))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Plan.Mode != plan.ModeHost || resp.Plan.Link.BirthName != plan.BirthName("c1") {
		t.Fatalf("plan = %+v", resp.Plan.Link)
	}
}

func TestResolveErrors(t *testing.T) {
	good := conf("203.0.113.7:51820")
	cases := []struct {
		name        string
		annotations map[string]string
		secret      *corev1.Secret
		want        string
	}{
		{"missing secret", map[string]string{agentapi.AnnotationSecret: "nope"}, nil,
			`secret "nope" (annotation zora.io/wireguard-secret) not found in namespace "apps"`},
		{"missing key", map[string]string{agentapi.AnnotationSecret: "wg"}, secret("wg", map[string]string{"other": good}),
			`secret "wg" has no key "wg0.conf"`},
		{"parse error with line", map[string]string{agentapi.AnnotationSecret: "wg"},
			secret("wg", map[string]string{"wg0.conf": strings.Replace(good, "Address", "Addr", 1)}),
			`secret "wg" key "wg0.conf": line 3: unknown key "Addr"`},
		{"duplicate section", map[string]string{agentapi.AnnotationSecret: "wg"},
			secret("wg", map[string]string{"wg0.conf": good + "\n[Interface]\n"}), "duplicate [Interface]"},
		{"post-up", map[string]string{agentapi.AnnotationSecret: "wg"},
			secret("wg", map[string]string{"wg0.conf": strings.Replace(good, "Address", "PostUp = id\nAddress", 1)}),
			"PostUp is not supported"},
		{"bad mode", map[string]string{agentapi.AnnotationSecret: "wg", agentapi.AnnotationMode: "sideways"},
			secret("wg", map[string]string{"wg0.conf": good}), `zora.io/wireguard-mode="sideways" is invalid`},
		{"unresolvable endpoint", map[string]string{agentapi.AnnotationSecret: "wg"},
			secret("wg", map[string]string{"wg0.conf": conf("gone.example.com:51820")}), `resolving endpoint "gone.example.com"`},
		{"plan error", map[string]string{agentapi.AnnotationSecret: "wg", agentapi.AnnotationIfName: "eth0"},
			secret("wg", map[string]string{"wg0.conf": good}), "collides"},
		{"address in pod cidr", map[string]string{agentapi.AnnotationSecret: "wg"},
			secret("wg", map[string]string{"wg0.conf": strings.Replace(good, "100.64.0.2", "10.244.9.9", 1)}), "overlaps cluster range"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := pod("vpn", c.annotations)
			objs := []runtime.Object{p}
			if c.secret != nil {
				objs = append(objs, c.secret)
			}
			e := newEnv(t, true, objs...)
			_, err := e.Resolve(context.Background(), request(p))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to contain %q", err, c.want)
			}
			ev := e.drainEvents()
			if len(ev) != 1 || !strings.HasPrefix(ev[0], "Warning "+ReasonConfigError) || !strings.Contains(ev[0], c.want) {
				t.Fatalf("events = %v; want one %s warning carrying the error", ev, ReasonConfigError)
			}
			for _, secretText := range []string{ifaceKey, ifaceKey[:12]} {
				if strings.Contains(err.Error()+ev[0], secretText) {
					t.Fatalf("the private key leaked into the error or event: %v / %v", err, ev)
				}
			}
		})
	}
}

func TestResolveForbiddenSecret(t *testing.T) {
	p := pod("vpn", map[string]string{agentapi.AnnotationSecret: "wg"})
	e := newEnv(t, true, p)
	e.client.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "wg", errors.New("RBAC"))
	})
	_, err := e.Resolve(context.Background(), request(p))
	if err == nil || !strings.Contains(err.Error(), `may not read secrets in namespace "apps"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestResolvePodIdentity(t *testing.T) {
	ctx := context.Background()
	p := pod("vpn", nil)

	t.Run("unknown pod", func(t *testing.T) {
		e := newEnv(t, true)
		if _, err := e.Resolve(ctx, request(p)); err == nil || !strings.Contains(err.Error(), "looking up pod apps/vpn") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("stale cache, pod replaced", func(t *testing.T) {
		// The cache still holds the old, unannotated pod; the API server
		// has its replacement, which is annotated. Answering from the
		// cache would skip a pod that wants a tunnel.
		replacement := pod("vpn", map[string]string{agentapi.AnnotationSecret: "wg"})
		replacement.UID = "uid-new"
		e := newEnv(t, false, replacement, secret("wg", map[string]string{"wg0.conf": conf("203.0.113.7:51820")}))
		if err := e.cache.Add(p); err != nil {
			t.Fatal(err)
		}
		resp, err := e.Resolve(ctx, request(replacement))
		if err != nil || resp.Action != agentapi.ActionConfigure {
			t.Fatalf("resp %+v, err %v", resp, err)
		}
	})
	t.Run("sandbox of a pod that no longer exists", func(t *testing.T) {
		e := newEnv(t, true, p)
		req := request(p)
		req.Pod.UID = "uid-old"
		if _, err := e.Resolve(ctx, req); err == nil || !strings.Contains(err.Error(), "has been replaced") {
			t.Fatalf("err = %v", err)
		}
	})
}

func condition(t *testing.T, e *env, name string) *corev1.PodCondition {
	t.Helper()
	p, err := e.client.CoreV1().Pods("apps").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == agentapi.ReadyCondition {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

func TestReport(t *testing.T) {
	ctx := context.Background()
	p := pod("vpn", map[string]string{agentapi.AnnotationSecret: "wg"})
	// A condition the kubelet owns must survive our patch.
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionTrue}}
	e := newEnv(t, true, p)
	ref := request(p).Pod

	if err := e.Report(ctx, agentapi.ReportRequest{Pod: ref, OK: false, Error: "routes: file exists"}); err != nil {
		t.Fatal(err)
	}
	c := condition(t, e, "vpn")
	if c == nil || c.Status != corev1.ConditionFalse || c.Reason != ReasonSetupFailed || !strings.Contains(c.Message, "file exists") {
		t.Fatalf("condition after a failed ADD = %+v", c)
	}
	if e.Succeeded(p.UID) {
		t.Fatal("Succeeded after a failure")
	}
	if ev := e.drainEvents(); len(ev) != 1 || !strings.HasPrefix(ev[0], "Warning "+ReasonSetupFailed) {
		t.Fatalf("events = %v", ev)
	}

	if err := e.Report(ctx, agentapi.ReportRequest{Pod: ref, OK: true, Warnings: []string{"DNS is ignored"}}); err != nil {
		t.Fatal(err)
	}
	c = condition(t, e, "vpn")
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("condition after a successful ADD = %+v", c)
	}
	got, _ := e.client.CoreV1().Pods("apps").Get(ctx, "vpn", metav1.GetOptions{})
	if len(got.Status.Conditions) != 2 || !IsReady(got) {
		t.Fatalf("conditions = %+v; the kubelet's must be kept", got.Status.Conditions)
	}
	if !e.Succeeded(p.UID) {
		t.Fatal("Succeeded is false after a success")
	}
	ev := e.drainEvents()
	if len(ev) != 2 || !strings.Contains(ev[0], "DNS is ignored") || !strings.HasPrefix(ev[1], "Normal "+ReasonConfigured) {
		t.Fatalf("events = %v", ev)
	}

	e.Retain(map[types.UID]bool{})
	if e.Succeeded(p.UID) {
		t.Fatal("Retain kept a pod that is gone")
	}

	stale := ref
	stale.UID = "uid-old"
	if err := e.Report(ctx, agentapi.ReportRequest{Pod: stale, OK: true}); err == nil {
		t.Fatal("a report for a replaced pod was accepted")
	}
}

func TestHealthy(t *testing.T) {
	e := newEnv(t, true)
	synced := false
	e.Synced = func() bool { return synced }
	if err := e.Healthy(context.Background()); err == nil {
		t.Fatal("healthy before the cache synced")
	}
	synced = true
	if err := e.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
}
