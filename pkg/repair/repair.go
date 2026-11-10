// Package repair finds pods that asked for a WireGuard interface but are
// running without one, and gets them recreated.
//
// That happens when a pod's sandbox was created while zora was not in the
// CNI chain: before zora was installed on the node, or in the moment after
// the primary CNI rewrote its config and before zora re-inserted itself. The
// CNI plugin cannot fix such a pod (the runtime only calls ADD at sandbox
// creation), so the only repair is a new sandbox.
//
// Deleting pods is drastic, so the controller is conservative. It acts only
// when all of these hold: zora is currently installed (otherwise the
// replacement would be just as broken, forever); the pod has been running
// longer than a grace period; no successful ADD was reported for it; and,
// for deletion, a controller owns it and will recreate it.
package repair

import (
	"context"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/resolver"
)

// ReasonMissing is the Event reason for a pod running without its tunnel.
const ReasonMissing = "WireGuardMissing"

// Action is what to do about a pod running without its tunnel.
type Action string

const (
	// ActionDelete deletes pods that a controller will recreate, and only
	// emits an Event for bare pods.
	ActionDelete Action = "delete"
	// ActionEvent only emits an Event.
	ActionEvent Action = "event"
	// ActionNone disables repair.
	ActionNone Action = "none"
)

// ParseAction validates an action name.
func ParseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case ActionDelete, ActionEvent, ActionNone:
		return a, nil
	}
	return "", fmt.Errorf("unknown repair action %q: use %q, %q or %q", s, ActionDelete, ActionEvent, ActionNone)
}

// Reports is what the controller needs from the resolver.
type Reports interface {
	Succeeded(uid types.UID) bool
	Retain(live map[types.UID]bool)
	SetReady(ctx context.Context, pod *corev1.Pod, ready bool, reason, message string) error
}

// Controller repairs pods on one node.
type Controller struct {
	Client  kubernetes.Interface
	Pods    corelisters.PodLister
	Reports Reports
	Events  record.EventRecorder
	Node    string
	Action  Action
	// Grace is how long a pod may run without the condition before it is
	// considered broken. It covers the time between a sandbox starting
	// and the plugin's report arriving.
	Grace time.Duration
	// ExcludeNamespaces are never configured by the plugin, so their pods
	// are never repaired.
	ExcludeNamespaces []string
	// Installed reports whether zora is currently in the CNI chain.
	Installed func() bool
	Now       func() time.Time
}

// Outcome is what RunOnce did about one pod.
type Outcome struct {
	Pod    string // namespace/name
	Action string // "deleted", "event", "marked-ready"
}

// RunOnce makes one pass over the node's pods.
func (c *Controller) RunOnce(ctx context.Context) ([]Outcome, error) {
	pods, err := c.Pods.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	live := map[types.UID]bool{}
	for _, p := range pods {
		live[p.UID] = true
	}
	c.Reports.Retain(live)
	if c.Action == ActionNone {
		return nil, nil
	}
	var out []Outcome
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	for _, pod := range pods {
		if pod.Spec.NodeName != c.Node ||
			pod.Annotations[agentapi.AnnotationSecret] == "" ||
			pod.Spec.HostNetwork || // no sandbox netns, so no CNI
			pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			slices.Contains(c.ExcludeNamespaces, pod.Namespace) ||
			resolver.IsReady(pod) {
			continue
		}
		name := pod.Namespace + "/" + pod.Name
		if c.Reports.Succeeded(pod.UID) {
			// The tunnel is up; only the condition is missing (the patch
			// failed, or something removed it).
			if err := c.Reports.SetReady(ctx, pod, true, resolver.ReasonConfigured, "WireGuard interface configured"); err != nil {
				return out, err
			}
			out = append(out, Outcome{name, "marked-ready"})
			continue
		}
		if !c.Installed() || pod.Status.StartTime == nil || now.Sub(pod.Status.StartTime.Time) < c.Grace {
			continue
		}
		const why = "the pod is running without the WireGuard interface it requested: its sandbox was created while zora was not in the node's CNI chain"
		if c.Action == ActionEvent || metav1.GetControllerOf(pod) == nil {
			c.Events.Event(pod, corev1.EventTypeWarning, ReasonMissing, why+"; delete the pod to have it recreated with the interface")
			out = append(out, Outcome{name, "event"})
			continue
		}
		c.Events.Event(pod, corev1.EventTypeWarning, ReasonMissing, why+"; deleting it so its controller recreates it")
		err := c.Client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &pod.UID},
		})
		if err != nil && !apierrors.IsNotFound(err) {
			return out, fmt.Errorf("deleting pod %s: %w", name, err)
		}
		out = append(out, Outcome{name, "deleted"})
	}
	return out, nil
}
