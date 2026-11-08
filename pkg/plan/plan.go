// Package plan turns a WireGuard config plus facts about the cluster and the
// pod into a declarative description of the kernel state to create: one link,
// its WireGuard device settings, addresses, routes, policy rules and sysctls.
//
// Compute is a pure function, so every routing decision zora makes can be
// covered by golden files and property tests without root or a kernel. The
// netapply package turns a Plan into netlink calls.
//
// # Routing model
//
// With Table=auto (the default), every AllowedIPs prefix is routed through
// the tunnel using policy routing, in both modes:
//
//	31000  to <cluster carve-out> lookup main       pod/service CIDRs, node IPs
//	31050  ipproto udp sport <port> lookup main     pod mode, IPv4: see below
//	31100  lookup main suppress_prefixlength 0      main's specific routes win
//	31200  [not fwmark M] lookup 51820              everything else: tunnel
//	32766  lookup main                              (kernel default)
//
// Table 51820 holds a route per AllowedIPs prefix via the WireGuard link, and
// a blackhole for the same prefix at a worse metric. If the link disappears,
// tunnel traffic is dropped rather than leaking out of the pod's uplink (the
// "kill switch").
//
// In pod mode the WireGuard socket lives in the pod, so its own encrypted
// packets carry fwmark M and skip the tunnel table: they leave via the
// uplink and so via the primary CNI. In host mode the socket lives in the
// host netns, so no fwmark is needed.
//
// Replies to the socket arrive on the uplink without a mark, so with strict
// IPv4 reverse-path filtering (rp_filter=1, which pods inherit from hosts
// that use it) the kernel's reverse lookup would resolve to the tunnel and
// drop them as spoofed. wg-quick avoids this with iptables connmark rules;
// zora instead pins the socket to a known port in pod mode and adds rule
// 31050. The reverse-path lookup dissects ports (swapped), so it matches and
// resolves via main, without loosening rp_filter or needing netfilter.
package plan

import (
	"net/netip"

	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

// Mode selects where the WireGuard link (and its UDP socket) is created.
type Mode string

const (
	// ModePod creates the link inside the pod netns. Encrypted traffic
	// leaves through the primary CNI, so NetworkPolicy, SNAT and
	// observability still apply. This is the default.
	ModePod Mode = "pod"
	// ModeHost creates the link in the host netns and moves it into the
	// pod. Encrypted traffic leaves from the node, bypassing the primary
	// CNI. Only cluster admins may enable it.
	ModeHost Mode = "host"
)

// Routing constants. They match wg-quick where wg-quick has an equivalent.
const (
	TunnelTable       = 51820
	DefaultFwMark     = 0xca6c // 51820, as wg-quick uses
	MainTable         = 254
	DefaultMTU        = 1420
	WireGuardOverhead = 80 // IPv6 outer header + UDP + WireGuard
	MinIPv6MTU        = 1280

	PriorityCarveOut = 31000
	PrioritySocket   = 31050
	PrioritySuppress = 31100
	PriorityTunnel   = 31200

	// KillSwitchMetric is the metric of the blackhole that backs each
	// tunnel route. Any value above the tunnel route's metric (0) works.
	KillSwitchMetric = 65535

	// DefaultListenPort is used in pod mode when the config sets none. It
	// is only bound inside the pod's own netns.
	DefaultListenPort = 51820
	ProtoUDP          = 17

	DefaultIfName     = "wg0"
	DefaultUplinkName = "eth0"
	MaxIfNameLen      = 15 // IFNAMSIZ - 1
	hostBirthPrefix   = "zw-"
)

// ClusterInfo describes destinations that must never enter the tunnel, so
// the pod can still reach Services, DNS, other pods and be probed by the
// kubelet.
type ClusterInfo struct {
	PodCIDRs     []netip.Prefix `json:"podCIDRs,omitempty"`
	ServiceCIDRs []netip.Prefix `json:"serviceCIDRs,omitempty"`
	NodeIPs      []netip.Addr   `json:"nodeIPs,omitempty"`
	// ExtraExcludes are admin-configured additions, for example a
	// NodeLocal DNSCache address such as 169.254.20.10.
	ExtraExcludes []netip.Prefix `json:"extraExcludes,omitempty"`
}

// Input is everything Compute needs. Zero values select defaults where noted.
type Input struct {
	Config  *wgconfig.Config `json:"-"`
	Cluster ClusterInfo      `json:"cluster"`
	Mode    Mode             `json:"mode,omitempty"`   // default ModePod
	IfName  string           `json:"ifName,omitempty"` // default "wg0"
	// UplinkName is the pod's primary interface. Default "eth0".
	UplinkName string `json:"uplinkName,omitempty"`
	// UplinkMTU is the MTU of the interface encrypted traffic leaves
	// through: the pod uplink in pod mode, the host's in host mode. 0
	// means unknown.
	UplinkMTU    int  `json:"uplinkMTU,omitempty"`
	IPv6Disabled bool `json:"ipv6Disabled,omitempty"`
	// ContainerID names the temporary host-side link in host mode.
	ContainerID string `json:"containerID,omitempty"`
	// Resolved maps each endpoint DNS name to the address the agent
	// resolved it to. IP-literal endpoints need no entry.
	Resolved map[string]netip.Addr `json:"resolved,omitempty"`
}

// Plan is the desired kernel state for one pod.
type Plan struct {
	Mode      Mode           `json:"mode"`
	Link      Link           `json:"link"`
	Device    Device         `json:"device"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	Routes    []Route        `json:"routes,omitempty"`
	Rules     []Rule         `json:"rules,omitempty"`
	Sysctls   []Sysctl       `json:"sysctls,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
}

// Link is the WireGuard network interface.
type Link struct {
	Name string `json:"name"`
	MTU  int    `json:"mtu"`
	// BirthName is set in host mode: the link is created in the host
	// netns under this unique name, then moved into the pod and renamed.
	BirthName string `json:"birthName,omitempty"`
}

// Device is the WireGuard configuration applied to the link.
type Device struct {
	PrivateKey wgconfig.SecretKey `json:"privateKey"`
	ListenPort int                `json:"listenPort,omitempty"`
	FwMark     uint32             `json:"fwMark,omitempty"`
	Peers      []DevicePeer       `json:"peers"`
}

// DevicePeer is one peer, with its endpoint resolved to an address.
type DevicePeer struct {
	PublicKey           wgconfig.Key        `json:"publicKey"`
	PresharedKey        *wgconfig.SecretKey `json:"presharedKey,omitempty"`
	Endpoint            *netip.AddrPort     `json:"endpoint,omitempty"`
	AllowedIPs          []netip.Prefix      `json:"allowedIPs,omitempty"`
	PersistentKeepalive int                 `json:"persistentKeepalive,omitempty"`
}

// RouteType is the kernel route type.
type RouteType string

const (
	RouteUnicast   RouteType = "unicast"
	RouteBlackhole RouteType = "blackhole"
)

// Route is one routing table entry.
type Route struct {
	Type   RouteType    `json:"type"`
	Dst    netip.Prefix `json:"dst"`
	Dev    string       `json:"dev,omitempty"` // empty for blackholes
	Table  int          `json:"table"`
	Metric int          `json:"metric,omitempty"`
}

// Family is an address family.
type Family int

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

func familyOf(a netip.Addr) Family {
	if a.Is4() {
		return IPv4
	}
	return IPv6
}

// Rule is one policy routing rule (ip rule).
type Rule struct {
	Priority int           `json:"priority"`
	Family   Family        `json:"family"`
	Dst      *netip.Prefix `json:"dst,omitempty"`
	// Mark matches fwmark Mark (with a full mask). Invert negates the
	// whole selector, as in "ip rule add not fwmark M".
	Mark   uint32 `json:"mark,omitempty"`
	Invert bool   `json:"invert,omitempty"`
	// IPProto and SPort, when set, match the IP protocol and source port.
	IPProto uint8  `json:"ipProto,omitempty"`
	SPort   uint16 `json:"sport,omitempty"`
	Table   int    `json:"table"`
	// SuppressPrefixLength, when set, rejects lookup results whose prefix
	// length is less than or equal to it.
	SuppressPrefixLength *int `json:"suppressPrefixLength,omitempty"`
}

// Sysctl is a per-netns kernel setting, keyed in dotted form.
type Sysctl struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
