// Package routesim is a small model of Linux policy routing: rules evaluated
// in priority order, longest-prefix match within a table, metrics,
// blackholes, fwmark selectors (including "not") and suppress_prefixlength.
//
// It exists so routing properties can be checked cheaply and exhaustively in
// unit tests (see pkg/plan). The netns tests in pkg/netapply check the model
// against the real kernel's decisions ("ip route get"), so a property proved
// on the model holds in the kernel.
package routesim

import (
	"math/rand/v2"
	"net/netip"
	"slices"
)

// Results of Lookup other than a device name.
const (
	Blackhole   = "<blackhole>"
	Unreachable = "<unreachable>"
)

// Route is a routing table entry.
type Route struct {
	Table     int
	Dst       netip.Prefix
	Dev       string
	Blackhole bool
	Metric    int
}

// Rule is a policy routing rule.
type Rule struct {
	Priority             int
	IPv6                 bool
	Dst                  *netip.Prefix
	Mark                 uint32 // 0 means no fwmark selector; mask is always full
	Invert               bool
	IPProto              uint8  // 0 means any
	SPort                uint16 // 0 means any
	Table                int
	SuppressPrefixLength *int
}

// Netns is a set of routing tables and rules.
type Netns struct {
	tables map[int][]Route
	rules  []Rule
}

// New builds a model. Rules are evaluated in priority order, ties in the
// order given (as the kernel does for rules added in that order).
func New(routes []Route, rules []Rule) *Netns {
	n := &Netns{tables: map[int][]Route{}, rules: slices.Clone(rules)}
	for _, r := range routes {
		n.tables[r.Table] = append(n.tables[r.Table], r)
	}
	slices.SortStableFunc(n.rules, func(a, b Rule) int { return a.Priority - b.Priority })
	return n
}

// Flow is what a routing decision is made on.
type Flow struct {
	Dst   netip.Addr
	Mark  uint32
	Proto uint8
	SPort uint16
}

// Lookup returns the device a locally generated packet to dst with the given
// fwmark leaves by, or Blackhole or Unreachable. Rules with a protocol or
// port selector do not match.
func (n *Netns) Lookup(dst netip.Addr, mark uint32) string {
	return n.LookupFlow(Flow{Dst: dst, Mark: mark})
}

// LookupFlow is Lookup for a flow with a protocol and source port. To model
// the kernel's reverse-path check of an incoming packet, pass its source as
// Dst, its destination port as SPort and its fwmark (0 unless
// src_valid_mark and a mark are set).
func (n *Netns) LookupFlow(f Flow) string {
	dst := f.Dst
	for _, r := range n.rules {
		if r.IPv6 != dst.Is6() {
			continue
		}
		sel := (r.Dst == nil || r.Dst.Contains(dst)) && (r.Mark == 0 || r.Mark == f.Mark) &&
			(r.IPProto == 0 || r.IPProto == f.Proto) && (r.SPort == 0 || r.SPort == f.SPort)
		if r.Invert {
			sel = !sel
		}
		if !sel {
			continue
		}
		best, ok := lookup(n.tables[r.Table], dst)
		if !ok {
			continue
		}
		if r.SuppressPrefixLength != nil && best.Dst.Bits() <= *r.SuppressPrefixLength {
			continue
		}
		if best.Blackhole {
			return Blackhole
		}
		return best.Dev
	}
	return Unreachable
}

// lookup is longest-prefix match, then lowest metric.
func lookup(table []Route, dst netip.Addr) (Route, bool) {
	var best Route
	found := false
	for _, r := range table {
		if !r.Dst.Contains(dst) {
			continue
		}
		if !found || r.Dst.Bits() > best.Dst.Bits() || (r.Dst.Bits() == best.Dst.Bits() && r.Metric < best.Metric) {
			best, found = r, true
		}
	}
	return best, found
}

// Probes returns interesting destinations: the first, last and a random
// address of every prefix (except unspecified addresses), the extra addresses, and some random addresses of
// both families.
func Probes(rng *rand.Rand, prefixes []netip.Prefix, extra ...netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, p := range prefixes {
		p = p.Masked()
		out = append(out, p.Addr(), LastAddr(p), RandomIn(rng, p))
	}
	out = append(out, extra...)
	for range 8 {
		out = append(out,
			RandomIn(rng, netip.MustParsePrefix("0.0.0.0/0")),
			RandomIn(rng, netip.MustParsePrefix("::/0")))
	}
	// The kernel treats the unspecified address as local; no real packet is
	// sent to it, so it is not an interesting destination.
	return slices.DeleteFunc(out, netip.Addr.IsUnspecified)
}

// LastAddr returns the highest address in p.
func LastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// RandomIn returns a random address in p.
func RandomIn(rng *rand.Rand, p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		if rng.IntN(2) == 1 {
			b[i/8] |= 0x80 >> (i % 8)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
