package repair

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/resolver"
)

var now = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// broken returns a pod that needs repair: annotated, on this node, owned by
// a controller, running for five minutes, with no ready condition.
func broken(name string, mutate ...func(*corev1.Pod)) *corev1.Pod {
	isController := true
	started := metav1.NewTime(now.Add(-5 * time.Minute))
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: name, UID: types.UID("uid-" + name),
			Annotations:     map[string]string{agentapi.AnnotationSecret: "wg"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs", Controller: &isController}},
		},
		Spec:   corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, StartTime: &started},
	}
	for _, m := range mutate {
		m(p)
	}
	return p
}

func run(t *testing.T, action Action, installed bool, succeeded []types.UID, pods ...*corev1.Pod) ([]Outcome, *fake.Clientset, []string) {
	t.Helper()
	idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	var objs []runtime.Object
	for _, p := range pods {
		objs = append(objs, p)
		if err := idx.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	client := fake.NewClientset(objs...)
	events := record.NewFakeRecorder(50)
	lister := corelisters.NewPodLister(idx)
	res := &resolver.Resolver{Client: client, Pods: lister, Events: record.NewFakeRecorder(50)}
	for _, uid := range succeeded {
		for _, p := range pods {
			if p.UID == uid {
				if err := res.Report(context.Background(), agentapi.ReportRequest{
					Pod: agentapi.Pod{Namespace: p.Namespace, Name: p.Name, UID: string(uid)}, OK: true,
				}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	c := &Controller{
		Client: client, Pods: lister, Reports: res, Events: events, Node: "node-1",
		Action: action, Grace: time.Minute, ExcludeNamespaces: []string{"kube-system"},
		Installed: func() bool { return installed }, Now: func() time.Time { return now },
	}
	out, err := c.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	close(events.Events)
	var evs []string
	for e := range events.Events {
		evs = append(evs, e)
	}
	return out, client, evs
}

func exists(t *testing.T, client *fake.Clientset, p *corev1.Pod) bool {
	t.Helper()
	_, err := client.CoreV1().Pods(p.Namespace).Get(context.Background(), p.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestDeletesBrokenPods(t *testing.T) {
	p := broken("vpn")
	out, client, evs := run(t, ActionDelete, true, nil, p)
	if !slices.Equal(out, []Outcome{{"apps/vpn", "deleted"}}) || exists(t, client, p) {
		t.Fatalf("outcomes = %v, pod exists = %v", out, exists(t, client, p))
	}
	if len(evs) != 1 || !strings.Contains(evs[0], ReasonMissing) {
		t.Fatalf("events = %v", evs)
	}
}

// TestLeavesPodsAlone lists every reason not to touch a pod. Each one
// guards against deleting a healthy pod or looping forever.
func TestLeavesPodsAlone(t *testing.T) {
	cases := map[string]func(*corev1.Pod){
		"not annotated":       func(p *corev1.Pod) { p.Annotations = nil },
		"on another node":     func(p *corev1.Pod) { p.Spec.NodeName = "node-2" },
		"host network":        func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"being deleted":       func(p *corev1.Pod) { t := metav1.NewTime(now); p.DeletionTimestamp = &t; p.Finalizers = []string{"x"} },
		"not running yet":     func(p *corev1.Pod) { p.Status.Phase = corev1.PodPending },
		"excluded namespace":  func(p *corev1.Pod) { p.Namespace = "kube-system" },
		"within grace period": func(p *corev1.Pod) { t := metav1.NewTime(now.Add(-10 * time.Second)); p.Status.StartTime = &t },
		"no start time":       func(p *corev1.Pod) { p.Status.StartTime = nil },
		"already ready": func(p *corev1.Pod) {
			p.Status.Conditions = []corev1.PodCondition{{Type: agentapi.ReadyCondition, Status: corev1.ConditionTrue}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := broken("vpn", mutate)
			out, client, evs := run(t, ActionDelete, true, nil, p)
			if len(out) != 0 || len(evs) != 0 || !exists(t, client, p) {
				t.Fatalf("outcomes = %v, events = %v, exists = %v", out, evs, exists(t, client, p))
			}
		})
	}
}

func TestDoesNothingWhileNotInstalled(t *testing.T) {
	// Deleting now would recreate the pod just as broken, forever.
	p := broken("vpn")
	out, client, evs := run(t, ActionDelete, false, nil, p)
	if len(out) != 0 || len(evs) != 0 || !exists(t, client, p) {
		t.Fatalf("outcomes = %v, events = %v", out, evs)
	}
}

func TestBarePodsAreNeverDeleted(t *testing.T) {
	p := broken("vpn", func(p *corev1.Pod) { p.OwnerReferences = nil })
	out, client, evs := run(t, ActionDelete, true, nil, p)
	if !slices.Equal(out, []Outcome{{"apps/vpn", "event"}}) || !exists(t, client, p) {
		t.Fatalf("outcomes = %v, exists = %v; nothing would recreate a bare pod", out, exists(t, client, p))
	}
	if len(evs) != 1 || !strings.Contains(evs[0], "delete the pod") {
		t.Fatalf("events = %v", evs)
	}
}

func TestActionEventAndNone(t *testing.T) {
	p := broken("vpn")
	out, client, evs := run(t, ActionEvent, true, nil, p)
	if !slices.Equal(out, []Outcome{{"apps/vpn", "event"}}) || !exists(t, client, p) || len(evs) != 1 {
		t.Fatalf("event: outcomes = %v, events = %v", out, evs)
	}
	out, client, evs = run(t, ActionNone, true, nil, p)
	if len(out) != 0 || len(evs) != 0 || !exists(t, client, p) {
		t.Fatalf("none: outcomes = %v, events = %v", out, evs)
	}
}

func TestRestoresALostCondition(t *testing.T) {
	// The ADD succeeded, but the pod has no condition (the cache here
	// predates the patch; in production the patch may have failed). The
	// tunnel is up, so the pod must be marked ready, not deleted. This
	// holds even when zora is not installed right now.
	p := broken("vpn")
	out, client, _ := run(t, ActionDelete, false, []types.UID{p.UID}, p)
	if !slices.Equal(out, []Outcome{{"apps/vpn", "marked-ready"}}) || !exists(t, client, p) {
		t.Fatalf("outcomes = %v, exists = %v", out, exists(t, client, p))
	}
	got, _ := client.CoreV1().Pods("apps").Get(context.Background(), "vpn", metav1.GetOptions{})
	if !resolver.IsReady(got) {
		t.Fatalf("conditions = %+v", got.Status.Conditions)
	}
}

func TestForgetsDeletedPods(t *testing.T) {
	// "gone" has left the node (it is in the API server, so its report is
	// accepted, but not in the node's pod cache). Its record must not
	// accumulate forever.
	live, gone := broken("live"), broken("gone")
	idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := idx.Add(live); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset(live, gone)
	lister := corelisters.NewPodLister(idx)
	res := &resolver.Resolver{Client: client, Pods: lister}
	for _, p := range []*corev1.Pod{live, gone} {
		if err := res.Report(context.Background(), agentapi.ReportRequest{
			Pod: agentapi.Pod{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID)}, OK: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	c := &Controller{Client: client, Pods: lister, Reports: res, Events: record.NewFakeRecorder(5), Node: "node-1",
		Action: ActionNone, Installed: func() bool { return true }}
	if _, err := c.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !res.Succeeded(live.UID) || res.Succeeded(gone.UID) {
		t.Fatalf("live remembered = %v, gone remembered = %v", res.Succeeded(live.UID), res.Succeeded(gone.UID))
	}
}

func TestParseAction(t *testing.T) {
	for _, s := range []string{"delete", "event", "none"} {
		if a, err := ParseAction(s); err != nil || string(a) != s {
			t.Errorf("ParseAction(%q) = %v, %v", s, a, err)
		}
	}
	if _, err := ParseAction("restart"); err == nil {
		t.Error("accepted an unknown action")
	}
}
