package plan

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

// Error is a configuration that cannot be turned into a safe plan. Messages
// are suitable for pod Events.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errorf(format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf(format, args...)}
}

// Compute derives the kernel state for in. It does no I/O.
func Compute(in Input) (*Plan, error) {
	c := in.Config
	if c == nil {
		return nil, errors.New("plan: nil config")
	}
	mode := cmp.Or(in.Mode, ModePod)
	if mode != ModePod && mode != ModeHost {
		return nil, errorf("unknown mode %q", in.Mode)
	}
	ifName := cmp.Or(in.IfName, DefaultIfName)
	uplink := cmp.Or(in.UplinkName, DefaultUplinkName)
	if err := validateIfName(ifName); err != nil {
		return nil, err
	}
	if ifName == uplink || ifName == "lo" {
		return nil, errorf("interface name %q collides with an existing pod interface", ifName)
	}
	if len(c.Peers) == 0 {
		return nil, errorf("config has no [Peer] sections")
	}
	tableMode := cmp.Or(c.Interface.Table.Mode, wgconfig.TableAuto)
	if tableMode == wgconfig.TableID {
		return nil, errorf("Table=%d is not supported: zora manages policy routing itself; use Table=auto or Table=off", c.Interface.Table.ID)
	}

	p := &Plan{Mode: mode, Link: Link{Name: ifName}}
	for _, w := range c.Warnings {
		p.Warnings = append(p.Warnings, w.String())
	}
	enabled := func(f Family) bool { return f == IPv4 || !in.IPv6Disabled }
	carveOuts := collectCarveOuts(in.Cluster)

	if mode == ModeHost {
		if in.ContainerID == "" {
			return nil, errorf("host mode requires a container ID")
		}
		p.Link.BirthName = BirthName(in.ContainerID)
	}

	// Addresses.
	hasV6Addr := false
	for _, a := range c.Interface.Addresses {
		f := familyOf(a.Addr())
		if !enabled(f) {
			p.Warnings = append(p.Warnings, fmt.Sprintf("address %s skipped: IPv6 is disabled in the pod", a))
			continue
		}
		for _, co := range carveOuts {
			if a.Masked().Overlaps(co) {
				return nil, errorf("interface address %s overlaps cluster range %s; traffic to the cluster would enter the tunnel", a, co)
			}
		}
		hasV6Addr = hasV6Addr || f == IPv6
		p.Addresses = append(p.Addresses, a)
	}

	// MTU.
	switch {
	case c.Interface.MTU != 0:
		p.Link.MTU = c.Interface.MTU
	case in.UplinkMTU != 0:
		p.Link.MTU = in.UplinkMTU - WireGuardOverhead
		if p.Link.MTU < 576 {
			return nil, errorf("uplink MTU %d is too small for WireGuard", in.UplinkMTU)
		}
	default:
		p.Link.MTU = DefaultMTU
	}
	if hasV6Addr && p.Link.MTU < MinIPv6MTU {
		return nil, errorf("MTU %d is below the IPv6 minimum of %d, but an IPv6 address is configured", p.Link.MTU, MinIPv6MTU)
	}

	// Tunnel prefixes: every AllowedIPs prefix of an enabled family.
	var tunnel []netip.Prefix
	skippedV6 := false
	for _, peer := range c.Peers {
		for _, pfx := range peer.AllowedIPs {
			if !enabled(familyOf(pfx.Addr())) {
				skippedV6 = true
				continue
			}
			tunnel = append(tunnel, pfx.Masked())
		}
	}
	if skippedV6 {
		p.Warnings = append(p.Warnings, "IPv6 AllowedIPs are not routed: IPv6 is disabled in the pod")
	}
	slices.SortFunc(tunnel, compareTunnelPrefix)
	tunnel = slices.Compact(tunnel)

	// Device.
	p.Device.PrivateKey = c.Interface.PrivateKey
	p.Device.ListenPort = int(c.Interface.ListenPort)
	p.Device.FwMark = c.Interface.FwMark
	policyRouting := tableMode == wgconfig.TableAuto && len(tunnel) > 0
	if mode == ModeHost {
		if p.Device.ListenPort != 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"ListenPort %d ignored in host mode: the socket is on the node, so a random port avoids clashing with other pods and the node's own WireGuard", p.Device.ListenPort))
			p.Device.ListenPort = 0
		}
		if p.Device.FwMark != 0 {
			p.Warnings = append(p.Warnings, "FwMark ignored in host mode: it would apply to the node's routing, not the pod's")
			p.Device.FwMark = 0
		}
	} else if policyRouting {
		if p.Device.FwMark == 0 {
			p.Device.FwMark = DefaultFwMark
		}
		if p.Device.ListenPort == 0 {
			p.Device.ListenPort = DefaultListenPort // rule 31050 needs a known port
		}
	}

	for _, peer := range c.Peers {
		dp := DevicePeer{
			PublicKey:           peer.PublicKey,
			AllowedIPs:          slices.Clone(peer.AllowedIPs),
			PersistentKeepalive: int(peer.PersistentKeepalive),
		}
		if peer.PresharedKey != nil {
			psk := *peer.PresharedKey
			dp.PresharedKey = &psk
		}
		if peer.Endpoint != nil {
			ep, err := resolveEndpoint(*peer.Endpoint, in.Resolved)
			if err != nil {
				return nil, err
			}
			if mode == ModePod {
				if ep.Addr().Is6() && in.IPv6Disabled {
					return nil, errorf("endpoint %s is IPv6, but IPv6 is disabled in the pod", peer.Endpoint)
				}
				// The interface's connected routes live in main, which the
				// socket's own (marked) packets still consult.
				for _, a := range p.Addresses {
					if a.Masked().Contains(ep.Addr()) {
						return nil, errorf("endpoint %s is inside the interface's own subnet %s; its packets would loop through the tunnel", ep, a.Masked())
					}
				}
			}
			dp.Endpoint = &ep
		}
		p.Device.Peers = append(p.Device.Peers, dp)
	}

	if tableMode == wgconfig.TableOff {
		return p, nil
	}
	if len(tunnel) == 0 {
		p.Warnings = append(p.Warnings, "no AllowedIPs: the tunnel carries no traffic")
		return p, nil
	}

	// Routes: each tunnel prefix via the link, backed by a blackhole.
	families := map[Family]bool{}
	for _, pfx := range tunnel {
		families[familyOf(pfx.Addr())] = true
		for _, co := range carveOuts {
			if co.Bits() <= pfx.Bits() && co.Contains(pfx.Addr()) {
				p.Warnings = append(p.Warnings, fmt.Sprintf(
					"AllowedIPs %s is inside cluster range %s, so it is not routed through the tunnel", pfx, co))
				break
			}
		}
		p.Routes = append(p.Routes,
			Route{Type: RouteUnicast, Dst: pfx, Dev: ifName, Table: TunnelTable},
			Route{Type: RouteBlackhole, Dst: pfx, Table: TunnelTable, Metric: KillSwitchMetric},
		)
	}

	// Rules, per family that has tunnel routes.
	zero := 0
	for _, f := range []Family{IPv4, IPv6} {
		if !families[f] {
			continue
		}
		for _, co := range carveOuts {
			if familyOf(co.Addr()) == f {
				p.Rules = append(p.Rules, Rule{Priority: PriorityCarveOut, Family: f, Dst: &co, Table: MainTable})
			}
		}
		if mode == ModePod && f == IPv4 {
			// Lets replies to the socket pass strict rp_filter; see the
			// package documentation.
			p.Rules = append(p.Rules, Rule{Priority: PrioritySocket, Family: f, IPProto: ProtoUDP,
				SPort: uint16(p.Device.ListenPort), Table: MainTable}) // #nosec G115 -- a port
		}
		p.Rules = append(p.Rules, Rule{Priority: PrioritySuppress, Family: f, Table: MainTable, SuppressPrefixLength: &zero})
		tunnelRule := Rule{Priority: PriorityTunnel, Family: f, Table: TunnelTable}
		if mode == ModePod {
			tunnelRule.Mark, tunnelRule.Invert = p.Device.FwMark, true
		}
		p.Rules = append(p.Rules, tunnelRule)
	}
	if mode == ModePod && families[IPv4] {
		// Lets reverse-path filtering see the fwmark, as wg-quick does.
		p.Sysctls = append(p.Sysctls, Sysctl{Key: "net.ipv4.conf.all.src_valid_mark", Value: "1"})
	}
	return p, nil
}

// BirthName is the temporary host-side name of a host-mode link for the
// given container. It is deterministic so CNI DEL can clean up a link that a
// failed ADD left in the host netns without asking the agent.
func BirthName(containerID string) string {
	sum := sha256.Sum256([]byte(containerID))
	return hostBirthPrefix + hex.EncodeToString(sum[:])[:MaxIfNameLen-len(hostBirthPrefix)]
}

// IsBirthName reports whether name has the shape BirthName produces.
func IsBirthName(name string) bool {
	if len(name) != MaxIfNameLen || !strings.HasPrefix(name, hostBirthPrefix) {
		return false
	}
	_, err := hex.DecodeString(name[len(hostBirthPrefix):])
	return err == nil
}

func validateIfName(name string) error {
	if len(name) > MaxIfNameLen || name == "." || name == ".." {
		return errorf("interface name %q must be 1-%d characters", name, MaxIfNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isAlnum(c) && c != '-' && c != '_' && c != '.' {
			return errorf("interface name %q may only contain letters, digits, '-', '_' and '.'", name)
		}
	}
	if strings.HasPrefix(name, hostBirthPrefix) {
		return errorf("interface name %q uses the prefix %q reserved by zora", name, hostBirthPrefix)
	}
	return nil
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func resolveEndpoint(ep wgconfig.Endpoint, resolved map[string]netip.Addr) (netip.AddrPort, error) {
	if a, ok := ep.Addr(); ok {
		return netip.AddrPortFrom(a, ep.Port), nil
	}
	a, ok := resolved[ep.Host]
	if !ok || !a.IsValid() {
		return netip.AddrPort{}, errorf("endpoint host %q has not been resolved", ep.Host)
	}
	return netip.AddrPortFrom(a.Unmap(), ep.Port), nil
}

func collectCarveOuts(ci ClusterInfo) []netip.Prefix {
	var out []netip.Prefix
	for _, group := range [][]netip.Prefix{ci.PodCIDRs, ci.ServiceCIDRs, ci.ExtraExcludes} {
		for _, p := range group {
			out = append(out, p.Masked())
		}
	}
	for _, a := range ci.NodeIPs {
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	slices.SortFunc(out, comparePrefix)
	return slices.Compact(out)
}

// comparePrefix orders IPv4 before IPv6, then by address, then by length.
func comparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// compareTunnelPrefix orders IPv4 before IPv6, then most specific first, as
// wg-quick does, then by address.
func compareTunnelPrefix(a, b netip.Prefix) int {
	return cmp.Or(
		cmp.Compare(familyOf(a.Addr()), familyOf(b.Addr())),
		cmp.Compare(b.Bits(), a.Bits()),
		a.Addr().Compare(b.Addr()),
	)
}
