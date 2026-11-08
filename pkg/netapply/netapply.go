// Package netapply makes a plan.Plan real: it creates the WireGuard link,
// configures the device, and installs addresses, routes, policy rules and
// sysctls in a pod's network namespace.
//
// Apply is all-or-nothing and safe to retry: it first clears any state a
// previous attempt left behind, and on failure it removes everything it
// created. Remove is idempotent and tolerates a namespace that no longer
// exists, as CNI DEL requires. Verify reports any difference between the
// kernel and the plan, for CNI CHECK.
//
// All decisions live in pkg/plan; this package only translates. Its tests run
// in throwaway namespaces (see internal/testns) and push real traffic through
// real tunnels.
package netapply

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tyler-lloyd/zora/internal/nsutil"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

// Options configures where links are created.
type Options struct {
	// HostNS is the namespace host-mode links are born in. Empty means the
	// calling process's namespace, which for the CNI plugin is the host's.
	HostNS string
}

// Apply steps, in order. Each is a failure-injection point for tests.
const (
	StepBirth     = "birth" // host mode: create the link in the host netns
	StepMove      = "move"  // host mode: move it into the pod
	StepSysctls   = "sysctls"
	StepLink      = "link"
	StepDevice    = "device"
	StepAddresses = "addresses"
	StepUp        = "up"
	StepRoutes    = "routes"
	StepRules     = "rules"
)

// Steps lists every step in the order Apply runs them.
var Steps = []string{StepBirth, StepMove, StepSysctls, StepLink, StepDevice, StepAddresses, StepUp, StepRoutes, StepRules}

// failpoint lets tests inject a failure before a step.
var failpoint = func(string) error { return nil }

// ownedRulePriorities are the rule priorities zora installs. Remove deletes
// rules at these priorities that point at the tables zora uses.
var ownedRulePriorities = []int{plan.PriorityCarveOut, plan.PrioritySocket, plan.PrioritySuppress, plan.PriorityTunnel}

// Apply makes the pod namespace at podNS match p.
func Apply(podNS string, p *plan.Plan, opts Options) (err error) {
	if err := Remove(podNS, p, opts); err != nil {
		return fmt.Errorf("clearing state from a previous attempt: %w", err)
	}
	defer func() {
		if err != nil {
			if rerr := Remove(podNS, p, opts); rerr != nil {
				err = errors.Join(err, fmt.Errorf("rolling back: %w", rerr))
			}
		}
	}()
	if p.Mode == plan.ModeHost {
		if err := birth(podNS, p, opts); err != nil {
			return err
		}
	}
	return nsutil.Do(podNS, func() error { return applyInPod(p) })
}

func step(name string, fn func() error) error {
	if err := failpoint(name); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := fn(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// hostHandle returns a netlink handle for the host namespace.
func hostHandle(opts Options) (*netlink.Handle, error) {
	if opts.HostNS == "" {
		return netlink.NewHandle()
	}
	f, err := nsutil.Open(opts.HostNS)
	if err != nil {
		return nil, fmt.Errorf("host netns: %w", err)
	}
	defer func() { _ = f.Close() }()
	return netlink.NewHandleAt(netns.NsHandle(f.Fd())) // #nosec G115 -- fds fit in int
}

// birth creates the link in the host namespace, so its UDP socket lives
// there, and moves it into the pod under its temporary name.
func birth(podNS string, p *plan.Plan, opts Options) error {
	h, err := hostHandle(opts)
	if err != nil {
		return err
	}
	defer h.Close()
	var link netlink.Link
	if err := step(StepBirth, func() error {
		if err := h.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: p.Link.BirthName, MTU: p.Link.MTU}}); err != nil {
			return err
		}
		link, err = h.LinkByName(p.Link.BirthName)
		return err
	}); err != nil {
		return err
	}
	return step(StepMove, func() error {
		pod, err := nsutil.Open(podNS)
		if err != nil {
			return err
		}
		defer func() { _ = pod.Close() }()
		return h.LinkSetNsFd(link, int(pod.Fd())) // #nosec G115
	})
}

// applyInPod runs on a thread inside the pod namespace.
func applyInPod(p *plan.Plan) error {
	if err := step(StepSysctls, func() error {
		for _, s := range p.Sysctls {
			if err := writeSysctl(s.Key, s.Value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	var link netlink.Link
	if err := step(StepLink, func() error {
		if _, err := netlink.LinkByName(p.Link.Name); err == nil {
			return fmt.Errorf("interface %s already exists in the pod and was not created by zora", p.Link.Name)
		}
		if p.Mode == plan.ModeHost {
			born, err := netlink.LinkByName(p.Link.BirthName)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetName(born, p.Link.Name); err != nil {
				return err
			}
		} else if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: p.Link.Name}}); err != nil {
			return err
		}
		var err error
		if link, err = netlink.LinkByName(p.Link.Name); err != nil {
			return err
		}
		return netlink.LinkSetMTU(link, p.Link.MTU)
	}); err != nil {
		return err
	}

	if err := step(StepDevice, func() error { return configureDevice(p) }); err != nil {
		return err
	}

	if err := step(StepAddresses, func() error {
		for _, a := range p.Addresses {
			if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet(a)}); err != nil {
				return fmt.Errorf("%s: %w", a, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	// Routes via a link that is down are rejected, so bring it up first.
	if err := step(StepUp, func() error { return netlink.LinkSetUp(link) }); err != nil {
		return err
	}

	if err := step(StepRoutes, func() error {
		for _, r := range p.Routes {
			if err := netlink.RouteAdd(toRoute(r, link.Attrs().Index)); err != nil {
				return fmt.Errorf("%s %s table %d: %w", r.Type, r.Dst, r.Table, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return step(StepRules, func() error {
		for _, r := range p.Rules {
			if err := netlink.RuleAdd(toRule(r)); err != nil {
				return fmt.Errorf("rule priority %d: %w", r.Priority, err)
			}
		}
		return nil
	})
}

func configureDevice(p *plan.Plan) error {
	wg, err := wgctrl.New() // must be created inside the pod netns
	if err != nil {
		return err
	}
	defer func() { _ = wg.Close() }()
	priv := wgtypes.Key(p.Device.PrivateKey)
	port := p.Device.ListenPort
	mark := int(p.Device.FwMark)
	cfg := wgtypes.Config{PrivateKey: &priv, ListenPort: &port, FirewallMark: &mark, ReplacePeers: true}
	for _, dp := range p.Device.Peers {
		pc := wgtypes.PeerConfig{
			PublicKey:         wgtypes.Key(dp.PublicKey),
			ReplaceAllowedIPs: true,
		}
		if dp.PresharedKey != nil {
			psk := wgtypes.Key(*dp.PresharedKey)
			pc.PresharedKey = &psk
		}
		if dp.Endpoint != nil {
			pc.Endpoint = net.UDPAddrFromAddrPort(*dp.Endpoint)
		}
		if dp.PersistentKeepalive > 0 {
			d := time.Duration(dp.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		for _, a := range dp.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, *ipNet(a.Masked()))
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	return wg.ConfigureDevice(p.Link.Name, cfg)
}

// Remove deletes everything Apply creates for p. It succeeds if the pod
// namespace no longer exists, and never deletes an interface zora did not
// create (only WireGuard links with the plan's names).
func Remove(podNS string, p *plan.Plan, opts Options) error {
	var errs []error
	if p.Mode == plan.ModeHost {
		errs = append(errs, removeHostOrphan(p, opts))
	}
	if _, err := os.Stat(podNS); errors.Is(err, fs.ErrNotExist) {
		return errors.Join(errs...)
	}
	errs = append(errs, nsutil.Do(podNS, func() error { return removeInPod(p) }))
	return errors.Join(errs...)
}

func removeHostOrphan(p *plan.Plan, opts Options) error {
	h, err := hostHandle(opts)
	if err != nil {
		return err
	}
	defer h.Close()
	return deleteWireGuardLink(h, p.Link.BirthName)
}

func deleteWireGuardLink(h *netlink.Handle, name string) error {
	l, err := h.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if l.Type() != "wireguard" {
		return nil // not ours
	}
	return h.LinkDel(l)
}

func removeInPod(p *plan.Plan) error {
	h, err := netlink.NewHandle() // on this thread, so in the pod netns
	if err != nil {
		return err
	}
	defer h.Close()
	var errs []error
	errs = append(errs, deleteWireGuardLink(h, p.Link.Name))
	if p.Mode == plan.ModeHost {
		errs = append(errs, deleteWireGuardLink(h, p.Link.BirthName)) // moved but not renamed
	}
	tables := []int{plan.TunnelTable}
	for _, r := range p.Routes {
		tables = append(tables, r.Table)
	}
	slices.Sort(tables)
	tables = slices.Compact(tables)
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := h.RuleList(fam)
		if errors.Is(err, unix.EAFNOSUPPORT) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, r := range rules {
			if slices.Contains(ownedRulePriorities, r.Priority) &&
				(r.Table == plan.MainTable || slices.Contains(tables, r.Table)) {
				errs = append(errs, h.RuleDel(&r))
			}
		}
		for _, table := range tables {
			routes, err := h.RouteListFiltered(fam, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, r := range routes {
				errs = append(errs, h.RouteDel(&r))
			}
		}
	}
	return errors.Join(errs...)
}

// Verify reports every difference between the pod namespace and p.
func Verify(podNS string, p *plan.Plan) error {
	return nsutil.Do(podNS, func() error { return verifyInPod(p) })
}

func verifyInPod(p *plan.Plan) error {
	var errs []error
	mismatch := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	link, err := netlink.LinkByName(p.Link.Name)
	if err != nil {
		return fmt.Errorf("interface %s: %w", p.Link.Name, err)
	}
	attrs := link.Attrs()
	if link.Type() != "wireguard" {
		mismatch("interface %s is %s, not wireguard", p.Link.Name, link.Type())
	}
	if attrs.MTU != p.Link.MTU {
		mismatch("interface %s MTU is %d, want %d", p.Link.Name, attrs.MTU, p.Link.MTU)
	}
	if attrs.Flags&net.FlagUp == 0 {
		mismatch("interface %s is down", p.Link.Name)
	}

	errs = append(errs, verifyDevice(p))

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, want := range p.Addresses {
		if !slices.ContainsFunc(addrs, func(a netlink.Addr) bool { return prefixOf(a.IPNet) == want }) {
			mismatch("address %s missing from %s", want, p.Link.Name)
		}
	}

	for _, want := range p.Routes {
		fam := family(want.Dst.Addr())
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: want.Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(routes, func(r netlink.Route) bool { return routeMatches(r, want, attrs.Index) }) {
			mismatch("route %s %s table %d metric %d missing", want.Type, want.Dst, want.Table, want.Metric)
		}
	}

	for _, want := range p.Rules {
		fam := netlink.FAMILY_V4
		if want.Family == plan.IPv6 {
			fam = netlink.FAMILY_V6
		}
		rules, err := netlink.RuleList(fam)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(rules, func(r netlink.Rule) bool { return ruleMatches(r, want) }) {
			mismatch("IPv%d rule priority %d (table %d) missing or different", want.Family, want.Priority, want.Table)
		}
	}

	for _, s := range p.Sysctls {
		got, err := readSysctl(s.Key)
		if err != nil {
			errs = append(errs, err)
		} else if got != s.Value {
			mismatch("sysctl %s is %q, want %q", s.Key, got, s.Value)
		}
	}
	return errors.Join(errs...)
}

func verifyDevice(p *plan.Plan) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = wg.Close() }()
	dev, err := wg.Device(p.Link.Name)
	if err != nil {
		return fmt.Errorf("reading WireGuard device %s: %w", p.Link.Name, err)
	}
	var errs []error
	mismatch := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if dev.PrivateKey != wgtypes.Key(p.Device.PrivateKey.Clamped()) {
		mismatch("device private key differs")
	}
	if p.Device.ListenPort != 0 && dev.ListenPort != p.Device.ListenPort {
		mismatch("device listen port is %d, want %d", dev.ListenPort, p.Device.ListenPort)
	}
	if uint32(dev.FirewallMark) != p.Device.FwMark { // #nosec G115 -- the kernel stores a u32
		mismatch("device fwmark is %#x, want %#x", dev.FirewallMark, p.Device.FwMark)
	}
	if len(dev.Peers) != len(p.Device.Peers) {
		mismatch("device has %d peers, want %d", len(dev.Peers), len(p.Device.Peers))
	}
	for _, want := range p.Device.Peers {
		i := slices.IndexFunc(dev.Peers, func(got wgtypes.Peer) bool { return got.PublicKey == wgtypes.Key(want.PublicKey) })
		if i < 0 {
			mismatch("peer %s missing", want.PublicKey)
			continue
		}
		got := dev.Peers[i]
		var wantPSK wgtypes.Key
		if want.PresharedKey != nil {
			wantPSK = wgtypes.Key(*want.PresharedKey)
		}
		if got.PresharedKey != wantPSK {
			mismatch("peer %s preshared key differs", want.PublicKey)
		}
		var gotEP netip.AddrPort
		if got.Endpoint != nil {
			gotEP = got.Endpoint.AddrPort()
			gotEP = netip.AddrPortFrom(gotEP.Addr().Unmap(), gotEP.Port())
		}
		if want.Endpoint != nil && gotEP != *want.Endpoint {
			mismatch("peer %s endpoint is %s, want %s", want.PublicKey, gotEP, want.Endpoint)
		}
		if got.PersistentKeepaliveInterval != time.Duration(want.PersistentKeepalive)*time.Second {
			mismatch("peer %s keepalive is %s, want %ds", want.PublicKey, got.PersistentKeepaliveInterval, want.PersistentKeepalive)
		}
		var gotIPs, wantIPs []string
		for _, n := range got.AllowedIPs {
			gotIPs = append(gotIPs, prefixOf(&n).String())
		}
		for _, a := range want.AllowedIPs {
			wantIPs = append(wantIPs, a.Masked().String())
		}
		slices.Sort(gotIPs)
		slices.Sort(wantIPs)
		if !slices.Equal(gotIPs, wantIPs) {
			mismatch("peer %s allowed IPs are %v, want %v", want.PublicKey, gotIPs, wantIPs)
		}
	}
	return errors.Join(errs...)
}

func family(a netip.Addr) int {
	if a.Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// ipNet converts a prefix, keeping host bits (as an interface address needs).
func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func prefixOf(n *net.IPNet) netip.Prefix {
	a, _ := netip.AddrFromSlice(n.IP)
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones)
}

func toRoute(r plan.Route, linkIndex int) *netlink.Route {
	nr := &netlink.Route{
		Family:   family(r.Dst.Addr()),
		Dst:      ipNet(r.Dst),
		Table:    r.Table,
		Priority: r.Metric,
	}
	if r.Type == plan.RouteBlackhole {
		nr.Type = unix.RTN_BLACKHOLE
	} else {
		nr.LinkIndex = linkIndex
		nr.Scope = netlink.SCOPE_LINK
	}
	return nr
}

// kernelMetric is the metric the kernel stores: IPv6 turns 0 into 1024.
func kernelMetric(r plan.Route) int {
	if r.Metric == 0 && r.Dst.Addr().Is6() {
		return 1024
	}
	return r.Metric
}

func routeMatches(got netlink.Route, want plan.Route, linkIndex int) bool {
	dst := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if want.Dst.Addr().Is6() {
		dst = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	if got.Dst != nil {
		dst = prefixOf(got.Dst)
	}
	if dst != want.Dst || got.Priority != kernelMetric(want) {
		return false
	}
	if want.Type == plan.RouteBlackhole {
		return got.Type == unix.RTN_BLACKHOLE
	}
	return got.Type == unix.RTN_UNICAST && got.LinkIndex == linkIndex
}

func toRule(r plan.Rule) *netlink.Rule {
	nr := netlink.NewRule()
	nr.Priority = r.Priority
	nr.Family = netlink.FAMILY_V4
	if r.Family == plan.IPv6 {
		nr.Family = netlink.FAMILY_V6
	}
	nr.Table = r.Table
	if r.Dst != nil {
		nr.Dst = ipNet(*r.Dst)
	}
	if r.Mark != 0 {
		nr.Mark = r.Mark
		mask := uint32(0xffffffff)
		nr.Mask = &mask
	}
	nr.Invert = r.Invert
	if r.IPProto != 0 {
		nr.IPProto = int(r.IPProto)
	}
	if r.SPort != 0 {
		nr.Sport = netlink.NewRulePortRange(r.SPort, r.SPort)
	}
	if r.SuppressPrefixLength != nil {
		nr.SuppressPrefixlen = *r.SuppressPrefixLength
	}
	return nr
}

func ruleMatches(got netlink.Rule, want plan.Rule) bool {
	if got.Priority != want.Priority || got.Table != want.Table || got.Invert != want.Invert ||
		got.Mark != want.Mark || got.IPProto != int(want.IPProto) {
		return false
	}
	var gotSPort uint16
	if got.Sport != nil {
		if got.Sport.Start != got.Sport.End {
			return false
		}
		gotSPort = got.Sport.Start
	}
	if gotSPort != want.SPort {
		return false
	}
	var gotDst netip.Prefix
	if got.Dst != nil {
		gotDst = prefixOf(got.Dst)
	}
	var wantDst netip.Prefix
	if want.Dst != nil {
		wantDst = *want.Dst
	}
	if gotDst != wantDst {
		return false
	}
	wantSuppress := -1
	if want.SuppressPrefixLength != nil {
		wantSuppress = *want.SuppressPrefixLength
	}
	return got.SuppressPrefixlen == wantSuppress
}

// sysctlKey guards against path traversal: plans come from the agent, but
// this code runs as root on the host.
var sysctlKey = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

func sysctlPath(key string) (string, error) {
	if !sysctlKey.MatchString(key) || !strings.HasPrefix(key, "net.") {
		return "", fmt.Errorf("refusing sysctl %q: only net.* keys are allowed", key)
	}
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/"), nil
}

func writeSysctl(key, value string) error {
	path, err := sysctlPath(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value), 0o644) // #nosec G306 -- sysctl files ignore the mode
}

func readSysctl(key string) (string, error) {
	path, err := sysctlPath(key)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path) // #nosec G304 -- validated above
	return strings.TrimSpace(string(b)), err
}
