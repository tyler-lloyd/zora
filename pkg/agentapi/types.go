// Package agentapi is the protocol between the zora-cni plugin (exec'd by the
// container runtime for every pod) and the zora-agent DaemonSet on the same
// node: HTTP+JSON over a unix socket.
//
// The plugin asks the agent what to do for a pod (Resolve), and tells it how
// that went (Report). The agent holds the Kubernetes credentials; the plugin
// holds the privileges. Keeping the plugin free of API access means a
// compromised or buggy plugin cannot read Secrets, and keeping netlink out of
// the agent means the agent needs no NET_ADMIN.
package agentapi

import (
	"net/netip"

	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

// Pod annotations. The agent interprets them; the plugin only looks at
// AnnotationSecret, to skip unannotated pods without a round trip when the
// runtime passes annotations to CNI plugins.
const (
	// AnnotationSecret names a Secret in the pod's namespace holding a
	// wg-quick config. Its presence opts the pod in.
	AnnotationSecret = "zora.io/wireguard-secret" // #nosec G101 -- an annotation name, not a credential
	// AnnotationKey is the Secret data key holding the config. Default
	// DefaultSecretKey.
	AnnotationKey = "zora.io/wireguard-key"
	// AnnotationIfName is the interface name in the pod. Default "wg0".
	AnnotationIfName = "zora.io/wireguard-ifname"
	// AnnotationMode requests "host" mode. The agent honours it only in
	// namespaces an admin has allowed.
	AnnotationMode = "zora.io/wireguard-mode"

	DefaultSecretKey = "wg0.conf"

	// ReadyCondition is the pod condition the agent sets once the tunnel
	// is up; usable as a readiness gate.
	ReadyCondition = "zora.io/wireguard-ready"
)

// DefaultSocket is where the agent listens.
const DefaultSocket = "/var/run/zora/zora.sock"

// HTTP paths.
const (
	PathResolve = "/v1/resolve"
	PathReport  = "/v1/report"
	PathHealth  = "/healthz"
)

// Pod identifies the pod a CNI operation is for, from CNI_ARGS.
type Pod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// UID lets the agent detect that the pod it looked up is not the one
	// being created (a same-named pod that was deleted and recreated).
	UID string `json:"uid,omitempty"`
}

// ResolveRequest asks what to do for a pod sandbox.
type ResolveRequest struct {
	Pod         Pod    `json:"pod"`
	ContainerID string `json:"containerID"`
	// UplinkMTU is the MTU of the pod's primary interface, if known.
	UplinkMTU int `json:"uplinkMTU,omitempty"`
}

// Action is the agent's decision.
type Action string

const (
	// ActionSkip means the pod has no WireGuard config: do nothing.
	ActionSkip Action = "skip"
	// ActionConfigure means apply Plan.
	ActionConfigure Action = "configure"
)

// ResolveResponse is the agent's decision for a pod.
type ResolveResponse struct {
	Action Action `json:"action"`
	// Plan is set for ActionConfigure. It contains the private key.
	Plan *WirePlan `json:"plan,omitempty"`
}

// ReportRequest tells the agent the outcome of an ADD.
type ReportRequest struct {
	Pod         Pod      `json:"pod"`
	ContainerID string   `json:"containerID"`
	OK          bool     `json:"ok"`
	Error       string   `json:"error,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// ErrorResponse is the body of every non-2xx response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// WirePlan is plan.Plan in transferable form. plan.Plan redacts its keys
// when marshalled (so it can be logged safely); this type carries them
// explicitly, as base64 strings, so the only way a key reaches the wire is
// through EncodePlan's calls to Base64. Never log a WirePlan.
//
// TestWirePlanCoversPlan fails when plan's types gain a field this type does
// not carry.
type WirePlan struct {
	Mode      plan.Mode      `json:"mode"`
	Link      plan.Link      `json:"link"`
	Device    WireDevice     `json:"device"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	Routes    []plan.Route   `json:"routes,omitempty"`
	Rules     []plan.Rule    `json:"rules,omitempty"`
	Sysctls   []plan.Sysctl  `json:"sysctls,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
}

// WireDevice is plan.Device with an explicit private key.
type WireDevice struct {
	PrivateKey string     `json:"privateKey"`
	ListenPort int        `json:"listenPort,omitempty"`
	FwMark     uint32     `json:"fwMark,omitempty"`
	Peers      []WirePeer `json:"peers"`
}

// WirePeer is plan.DevicePeer with an explicit preshared key.
type WirePeer struct {
	PublicKey           wgconfig.Key    `json:"publicKey"`
	PresharedKey        string          `json:"presharedKey,omitempty"`
	Endpoint            *netip.AddrPort `json:"endpoint,omitempty"`
	AllowedIPs          []netip.Prefix  `json:"allowedIPs,omitempty"`
	PersistentKeepalive int             `json:"persistentKeepalive,omitempty"`
}

// EncodePlan converts a plan for the wire.
func EncodePlan(p *plan.Plan) *WirePlan {
	w := &WirePlan{
		Mode: p.Mode, Link: p.Link, Addresses: p.Addresses, Routes: p.Routes,
		Rules: p.Rules, Sysctls: p.Sysctls, Warnings: p.Warnings,
		Device: WireDevice{
			PrivateKey: p.Device.PrivateKey.Base64(),
			ListenPort: p.Device.ListenPort,
			FwMark:     p.Device.FwMark,
		},
	}
	for _, dp := range p.Device.Peers {
		wp := WirePeer{
			PublicKey: dp.PublicKey, Endpoint: dp.Endpoint,
			AllowedIPs: dp.AllowedIPs, PersistentKeepalive: dp.PersistentKeepalive,
		}
		if dp.PresharedKey != nil {
			wp.PresharedKey = dp.PresharedKey.Base64()
		}
		w.Device.Peers = append(w.Device.Peers, wp)
	}
	return w
}

// Decode converts a wire plan back, validating its keys.
func (w *WirePlan) Decode() (*plan.Plan, error) {
	priv, err := wgconfig.ParseSecretKey(w.Device.PrivateKey)
	if err != nil {
		return nil, planError("private key", err)
	}
	p := &plan.Plan{
		Mode: w.Mode, Link: w.Link, Addresses: w.Addresses, Routes: w.Routes,
		Rules: w.Rules, Sysctls: w.Sysctls, Warnings: w.Warnings,
		Device: plan.Device{PrivateKey: priv, ListenPort: w.Device.ListenPort, FwMark: w.Device.FwMark},
	}
	for _, wp := range w.Device.Peers {
		dp := plan.DevicePeer{
			PublicKey: wp.PublicKey, Endpoint: wp.Endpoint,
			AllowedIPs: wp.AllowedIPs, PersistentKeepalive: wp.PersistentKeepalive,
		}
		if wp.PresharedKey != "" {
			psk, err := wgconfig.ParseSecretKey(wp.PresharedKey)
			if err != nil {
				return nil, planError("preshared key of peer "+wp.PublicKey.String(), err)
			}
			dp.PresharedKey = &psk
		}
		p.Device.Peers = append(p.Device.Peers, dp)
	}
	return p, nil
}

type decodeError struct {
	what string
	err  error
}

func (e *decodeError) Error() string {
	return "agent sent an invalid plan: " + e.what + ": " + e.err.Error()
}
func (e *decodeError) Unwrap() error { return e.err }

func planError(what string, err error) error { return &decodeError{what: what, err: err} }
