// Package resolver decides what zora does for a pod. It implements the agent
// side of pkg/agentapi: given the pod a CNI ADD is for, it reads the pod's
// annotations, fetches the Secret they name, validates the WireGuard config,
// resolves endpoint host names and computes the plan the plugin applies.
//
// Every failure is reported twice: as the error the plugin returns to the
// runtime (so the pod stays ContainerCreating and the kubelet retries), and
// as a Warning Event on the pod, where its owner will look. Neither ever
// contains key material; pkg/wgconfig guarantees that for parse errors, and
// nothing else here handles keys.
package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

// Event reasons.
const (
	ReasonConfigError = "WireGuardConfigError"
	ReasonSetupFailed = "WireGuardSetupFailed"
	ReasonConfigured  = "WireGuardConfigured"
	ReasonWarning     = "WireGuardConfigWarning"
)

// Values of the mode annotation.
const (
	ModePod  = "pod"
	ModeHost = "host"
)

// dnsTimeout bounds each endpoint lookup, well inside the plugin's timeout.
const dnsTimeout = 5 * time.Second

// DNS resolves endpoint host names. *net.Resolver implements it.
type DNS interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config is the cluster-level configuration, set by the admin.
type Config struct {
	// Cluster lists the ranges that must stay out of every tunnel.
	// NodeIPs is filled from NodeIPs at each Resolve.
	Cluster plan.ClusterInfo
	// NodeIPs returns this node's addresses. May be nil.
	NodeIPs func() []netip.Addr
	// HostModeNamespaces are the namespaces whose pods may use host mode,
	// which lets encrypted traffic bypass NetworkPolicy. A pod annotation
	// alone never enables it.
	HostModeNamespaces []string
}

// Resolver implements agentapi.Handler.
type Resolver struct {
	Client kubernetes.Interface
	// Pods is an informer-backed cache of this node's pods. Lookups fall
	// back to the API server, because a sandbox is often created before
	// the informer has seen its pod.
	Pods   corelisters.PodLister
	Synced func() bool
	Events record.EventRecorder
	DNS    DNS
	Config Config

	mu        sync.Mutex
	succeeded map[types.UID]bool
}

var _ agentapi.Handler = (*Resolver)(nil)

// Healthy implements agentapi.Handler.
func (r *Resolver) Healthy(context.Context) error {
	if r.Synced != nil && !r.Synced() {
		return errors.New("pod cache has not synced yet")
	}
	return nil
}

// pod finds the pod a request is about and checks it is the same incarnation.
func (r *Resolver) pod(ctx context.Context, ref agentapi.Pod) (*corev1.Pod, error) {
	if pod, err := r.Pods.Pods(ref.Namespace).Get(ref.Name); err == nil && (ref.UID == "" || string(pod.UID) == ref.UID) {
		return pod, nil
	}
	pod, err := r.Client.CoreV1().Pods(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("looking up pod %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	if ref.UID != "" && string(pod.UID) != ref.UID {
		return nil, fmt.Errorf("pod %s/%s has been replaced: the sandbox is for UID %s, the current pod is %s",
			ref.Namespace, ref.Name, ref.UID, pod.UID)
	}
	return pod, nil
}

// Resolve implements agentapi.Handler.
func (r *Resolver) Resolve(ctx context.Context, req agentapi.ResolveRequest) (*agentapi.ResolveResponse, error) {
	pod, err := r.pod(ctx, req.Pod)
	if err != nil {
		return nil, err
	}
	if pod.Annotations[agentapi.AnnotationSecret] == "" {
		return &agentapi.ResolveResponse{Action: agentapi.ActionSkip}, nil
	}
	p, err := r.plan(ctx, pod, req)
	if err != nil {
		r.event(pod, corev1.EventTypeWarning, ReasonConfigError, err.Error())
		return nil, err
	}
	return &agentapi.ResolveResponse{Action: agentapi.ActionConfigure, Plan: agentapi.EncodePlan(p)}, nil
}

func (r *Resolver) plan(ctx context.Context, pod *corev1.Pod, req agentapi.ResolveRequest) (*plan.Plan, error) {
	ann := pod.Annotations
	in := plan.Input{
		Cluster:     r.Config.Cluster,
		IfName:      ann[agentapi.AnnotationIfName],
		UplinkMTU:   req.UplinkMTU,
		ContainerID: req.ContainerID,
		Resolved:    map[string]netip.Addr{},
	}
	if r.Config.NodeIPs != nil {
		in.Cluster.NodeIPs = r.Config.NodeIPs()
	}
	switch mode := ann[agentapi.AnnotationMode]; mode {
	case "", ModePod:
		in.Mode = plan.ModePod
	case ModeHost:
		if !slices.Contains(r.Config.HostModeNamespaces, pod.Namespace) {
			// Refuse rather than fall back to pod mode: the pod asked for
			// something specific and must not silently get something else.
			return nil, fmt.Errorf("annotation %s=%s is not allowed in namespace %q: a cluster admin must add the namespace to zora's host-mode namespaces",
				agentapi.AnnotationMode, mode, pod.Namespace)
		}
		in.Mode = plan.ModeHost
	default:
		return nil, fmt.Errorf("annotation %s=%q is invalid: use %q or %q", agentapi.AnnotationMode, mode, ModePod, ModeHost)
	}

	secretName := ann[agentapi.AnnotationSecret]
	key := ann[agentapi.AnnotationKey]
	if key == "" {
		key = agentapi.DefaultSecretKey
	}
	secret, err := r.Client.CoreV1().Secrets(pod.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return nil, fmt.Errorf("secret %q (annotation %s) not found in namespace %q", secretName, agentapi.AnnotationSecret, pod.Namespace)
	case apierrors.IsForbidden(err):
		return nil, fmt.Errorf("zora may not read secrets in namespace %q: a cluster admin must enable zora for the namespace", pod.Namespace)
	case err != nil:
		return nil, fmt.Errorf("reading secret %q: %w", secretName, err)
	}
	data, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("secret %q has no key %q (set annotation %s to choose another key)", secretName, key, agentapi.AnnotationKey)
	}
	cfg, err := wgconfig.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("secret %q key %q: %w", secretName, key, err)
	}
	in.Config = cfg

	for _, peer := range cfg.Peers {
		ep := peer.Endpoint
		if ep == nil {
			continue
		}
		if _, literal := ep.Addr(); literal {
			continue
		}
		addr, err := r.lookup(ctx, ep.Host)
		if err != nil {
			return nil, fmt.Errorf("secret %q: resolving endpoint %q: %w", secretName, ep.Host, err)
		}
		in.Resolved[ep.Host] = addr
	}

	p, err := plan.Compute(in)
	if err != nil {
		return nil, fmt.Errorf("secret %q key %q: %w", secretName, key, err)
	}
	return p, nil
}

// lookup resolves host, preferring IPv4: every pod can reach an IPv4
// endpoint through its uplink, while IPv6 may be disabled.
func (r *Resolver) lookup(ctx context.Context, host string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	addrs, err := r.DNS.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			return a, nil
		}
		if !v6.IsValid() {
			v6 = a
		}
	}
	if !v6.IsValid() {
		return netip.Addr{}, errors.New("no addresses found")
	}
	return v6, nil
}

// Report implements agentapi.Handler: it records the outcome of an ADD as
// Events and as the pod's ReadyCondition.
func (r *Resolver) Report(ctx context.Context, req agentapi.ReportRequest) error {
	pod, err := r.pod(ctx, req.Pod)
	if err != nil {
		return err
	}
	if req.OK {
		r.mu.Lock()
		if r.succeeded == nil {
			r.succeeded = map[types.UID]bool{}
		}
		r.succeeded[pod.UID] = true
		r.mu.Unlock()
		for _, w := range req.Warnings {
			r.event(pod, corev1.EventTypeWarning, ReasonWarning, w)
		}
		r.event(pod, corev1.EventTypeNormal, ReasonConfigured, "WireGuard interface configured")
		return r.SetReady(ctx, pod, true, ReasonConfigured, "WireGuard interface configured")
	}
	r.event(pod, corev1.EventTypeWarning, ReasonSetupFailed, req.Error)
	return r.SetReady(ctx, pod, false, ReasonSetupFailed, req.Error)
}

// Succeeded reports whether a successful ADD was reported for the pod since
// this agent started.
func (r *Resolver) Succeeded(uid types.UID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.succeeded[uid]
}

// Retain forgets reports for pods not in live.
func (r *Resolver) Retain(live map[types.UID]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for uid := range r.succeeded {
		if !live[uid] {
			delete(r.succeeded, uid)
		}
	}
}

// IsReady reports whether the pod's ReadyCondition is true.
func IsReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == agentapi.ReadyCondition {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// SetReady sets the pod's ReadyCondition. Pods can list the condition under
// readinessGates to stay out of Services until their tunnel is configured.
func (r *Resolver) SetReady(ctx context.Context, pod *corev1.Pod, ready bool, reason, message string) error {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == agentapi.ReadyCondition && c.Status == status && c.Reason == reason {
			return nil
		}
	}
	now := metav1.Now()
	patch, err := json.Marshal(map[string]any{
		// The UID makes the API server reject the patch if the pod has
		// been replaced by another of the same name.
		"metadata": map[string]any{"uid": pod.UID},
		"status": map[string]any{"conditions": []corev1.PodCondition{{
			Type: agentapi.ReadyCondition, Status: status, Reason: reason,
			Message: truncate(message), LastProbeTime: now, LastTransitionTime: now,
		}}},
	})
	if err != nil {
		return err
	}
	_, err = r.Client.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status")
	if err != nil {
		return fmt.Errorf("setting condition %s on pod %s/%s: %w", agentapi.ReadyCondition, pod.Namespace, pod.Name, err)
	}
	return nil
}

func (r *Resolver) event(pod *corev1.Pod, eventType, reason, message string) {
	if r.Events != nil {
		r.Events.Event(pod, eventType, reason, truncate(message))
	}
}

// truncate keeps messages within the API's 1024-byte Event limit.
func truncate(s string) string {
	const limit = 1000
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
