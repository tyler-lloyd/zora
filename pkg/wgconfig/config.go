// Package wgconfig parses and validates wg-quick style WireGuard
// configurations, as stored in the Secret a pod references.
//
// The accepted format is the wg-quick(8) superset of wg(8)'s config format,
// minus everything that would run commands on the host (PreUp, PostUp,
// PreDown, PostDown) or write files (SaveConfig). The package is pure: it does
// no I/O, DNS resolution or kernel calls, which keeps it trivially testable
// and fuzzable.
package wgconfig

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// MaxConfigSize bounds parser input. It matches the Kubernetes Secret size
// limit, so any config that fits in a Secret is accepted.
const MaxConfigSize = 1 << 20

// Config is a parsed WireGuard configuration.
type Config struct {
	Interface Interface `json:"interface"`
	Peers     []Peer    `json:"peers,omitempty"`
	// Warnings are directives that were accepted but deliberately ignored.
	Warnings []Warning `json:"warnings,omitempty"`
}

// Interface is the [Interface] section.
type Interface struct {
	PrivateKey SecretKey      `json:"privateKey"`
	Addresses  []netip.Prefix `json:"addresses,omitempty"`
	// ListenPort 0 means unset: the kernel picks a random port.
	ListenPort uint16 `json:"listenPort,omitempty"`
	// FwMark 0 means off.
	FwMark uint32 `json:"fwMark,omitempty"`
	// MTU 0 means automatic.
	MTU   int   `json:"mtu,omitempty"`
	Table Table `json:"table"`
	// DNS is recorded but not applied: a pod's resolv.conf belongs to the
	// kubelet. Each entry is an IP address or a search domain.
	DNS []string `json:"dns,omitempty"`
}

// TableMode is wg-quick's Table= setting.
type TableMode string

const (
	// TableAuto installs routes for AllowedIPs, using policy routing for
	// default routes. It is the default.
	TableAuto TableMode = "auto"
	// TableOff installs no routes.
	TableOff TableMode = "off"
	// TableID installs routes into a specific routing table.
	TableID TableMode = "id"
)

// MainTable is the ID of the kernel's main routing table.
const MainTable = 254

// Table is wg-quick's Table= setting.
type Table struct {
	Mode TableMode `json:"mode"`
	// ID is set when Mode is TableID.
	ID uint32 `json:"id,omitempty"`
}

// Peer is one [Peer] section.
type Peer struct {
	PublicKey    Key            `json:"publicKey"`
	PresharedKey *SecretKey     `json:"presharedKey,omitempty"`
	AllowedIPs   []netip.Prefix `json:"allowedIPs,omitempty"`
	Endpoint     *Endpoint      `json:"endpoint,omitempty"`
	// PersistentKeepalive is in seconds; 0 means off.
	PersistentKeepalive uint16 `json:"persistentKeepalive,omitempty"`
}

// Endpoint is a peer's Endpoint=. Host is an IP literal or a DNS name; DNS
// names are resolved by the agent, never by this package.
type Endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// String returns host:port, bracketing IPv6 literals.
func (e Endpoint) String() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// Addr returns the endpoint's address if Host is an IP literal.
func (e Endpoint) Addr() (netip.Addr, bool) {
	a, err := netip.ParseAddr(e.Host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Warning is a non-fatal note about the config.
type Warning struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

func (w Warning) String() string { return fmt.Sprintf("line %d: %s", w.Line, w.Message) }

// ParseError reports an invalid config. Its message never contains key
// material: values of secret fields are never echoed, and unrecognised text is
// only echoed when it cannot be a key.
type ParseError struct {
	Line int // 1-based; 0 when the error is not tied to a line
	Msg  string
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}
