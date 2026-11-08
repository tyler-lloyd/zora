// Package testns gives tests throwaway network namespaces without root.
//
// Use it from TestMain:
//
//	func TestMain(m *testing.M) { testns.Main(m) }
//
// Main re-executes the test binary inside a new network namespace (and, when
// not root, a new user namespace that maps the caller to root). The tests
// therefore never touch the machine's real network, even when run as root,
// and need no sudo where unprivileged user namespaces are allowed.
//
// If namespaces are unavailable, tests that call New are skipped. CI sets
// ZORA_REQUIRE_NETNS=1, which turns those skips into failures so a broken
// runner can't silently pass.
package testns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/tyler-lloyd/zora/internal/nsutil"
)

const (
	envInside      = "ZORA_TESTNS_INSIDE"
	envUnavailable = "ZORA_TESTNS_UNAVAILABLE"
	// EnvRequire makes unavailable namespaces a test failure.
	EnvRequire = "ZORA_REQUIRE_NETNS"
)

// Main runs the tests inside fresh namespaces. It does not return.
func Main(m *testing.M) {
	if os.Getenv(envInside) == "1" {
		os.Exit(m.Run())
	}
	exe, err := os.Executable()
	if err == nil {
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = append(os.Environ(), envInside+"=1")
		attr := &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
		if os.Geteuid() != 0 {
			attr.Cloneflags |= syscall.CLONE_NEWUSER
			attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
			attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
			attr.GidMappingsEnableSetgroups = false
		}
		cmd.SysProcAttr = attr
		err = cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		if err == nil {
			os.Exit(0)
		}
	}
	// Could not create namespaces. Run anyway so non-netns tests still run
	// and netns tests report why they were skipped.
	reason := fmt.Sprintf("network namespaces unavailable: %v (unprivileged user namespaces may be disabled; try sudo)", err)
	_ = os.Setenv(envUnavailable, reason)
	os.Exit(m.Run())
}

func skipOrFail(t testing.TB, reason string) {
	t.Helper()
	if os.Getenv(EnvRequire) == "1" {
		t.Fatalf("%s (and %s=1)", reason, EnvRequire)
	}
	t.Skip(reason)
}

// NS is a throwaway network namespace.
type NS struct {
	Name string
	// Path is a filesystem path to the namespace, like CNI_NETNS.
	Path string
	// Handle performs netlink operations inside the namespace.
	Handle *netlink.Handle
	file   *os.File
}

// New creates a network namespace that is destroyed when the test ends.
func New(t testing.TB, name string) *NS {
	t.Helper()
	if reason := os.Getenv(envUnavailable); reason != "" {
		skipOrFail(t, reason)
	}
	f, err := newNetNS()
	if err != nil {
		skipOrFail(t, fmt.Sprintf("creating network namespace: %v", err))
	}
	h, err := netlink.NewHandleAt(netns.NsHandle(f.Fd())) // #nosec G115
	if err != nil {
		_ = f.Close()
		t.Fatalf("netlink handle for %s: %v", name, err)
	}
	ns := &NS{Name: name, Path: fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), f.Fd()), Handle: h, file: f}
	t.Cleanup(func() {
		h.Close()
		_ = f.Close()
	})
	ns.Must(t, ns.Handle.LinkSetUp(ns.Link(t, "lo")))
	// Skip IPv6 duplicate address detection so link-local addresses (and
	// their routes) appear promptly; see settle.
	ns.Sysctl(t, "net.ipv6.conf.default.accept_dad", "0")
	ns.Sysctl(t, "net.ipv6.conf.all.accept_dad", "0")
	return ns
}

// settle waits until the kernel has finished bringing up a link: its IPv6
// link-local address and local route are added asynchronously, and tests
// that snapshot the namespace must not race with that.
func (n *NS) settle(t testing.TB, name string) {
	t.Helper()
	var disabled string
	n.Do(t, func() error {
		b, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6")
		disabled = strings.TrimSpace(string(b))
		return err
	})
	if disabled == "1" {
		return
	}
	n.waitLocalRoute(t, name, "an IPv6 link-local address", func(a net.IP) bool { return a.IsLinkLocalUnicast() })
}

// waitLocalRoute polls the local table until dev has an IPv6 route whose
// destination satisfies match.
func (n *NS) waitLocalRoute(t testing.TB, dev, what string, match func(net.IP) bool) {
	t.Helper()
	link := n.Link(t, dev)
	for range 500 {
		routes, err := n.Handle.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: unix.RT_TABLE_LOCAL, LinkIndex: link.Attrs().Index},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
		n.Must(t, err)
		for _, r := range routes {
			if r.Dst != nil && match(r.Dst.IP) {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("netns %s: link %s never got the local route for %s", n.Name, dev, what)
}

// newNetNS creates a namespace and returns an fd that keeps it alive.
func newNetNS() (*os.File, error) {
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	defer func() { _ = self.Close() }()
	// DoFd restores the thread's original netns after fn, so unsharing
	// inside it leaves the calling goroutine's thread untouched.
	var f *os.File
	err = nsutil.DoFd(self, func() error {
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		var err error
		f, err = os.Open("/proc/thread-self/ns/net")
		return err
	})
	return f, err
}

// Do runs fn inside the namespace; sockets fn creates belong to it.
func (n *NS) Do(t testing.TB, fn func() error) {
	t.Helper()
	if err := nsutil.DoFd(n.file, fn); err != nil {
		t.Fatalf("in netns %s: %v", n.Name, err)
	}
}

// Must fails the test if err is non-nil.
func (n *NS) Must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("netns %s: %v", n.Name, err)
	}
}

// Link returns the named link or fails the test.
func (n *NS) Link(t testing.TB, name string) netlink.Link {
	t.Helper()
	l, err := n.Handle.LinkByName(name)
	n.Must(t, err)
	return l
}

// Veth connects a and b with a veth pair named aName (in a) and bName (in b),
// both up.
func Veth(t testing.TB, a *NS, aName string, b *NS, bName string) {
	t.Helper()
	tmp := "zv" + strings.ReplaceAll(bName, "-", "")
	if len(tmp) > 15 {
		tmp = tmp[:15]
	}
	a.Must(t, a.Handle.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: aName}, PeerName: tmp}))
	a.Must(t, a.Handle.LinkSetNsFd(a.Link(t, tmp), int(b.file.Fd()))) // #nosec G115
	b.Must(t, b.Handle.LinkSetName(b.Link(t, tmp), bName))
	a.Must(t, a.Handle.LinkSetUp(a.Link(t, aName)))
	b.Must(t, b.Handle.LinkSetUp(b.Link(t, bName)))
	a.settle(t, aName)
	b.settle(t, bName)
}

// Dummy adds an up dummy interface.
func (n *NS) Dummy(t testing.TB, name string) {
	t.Helper()
	n.Must(t, n.Handle.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}))
	n.Must(t, n.Handle.LinkSetUp(n.Link(t, name)))
	n.settle(t, name)
}

// Addr adds an address (CIDR with host bits, e.g. "10.0.0.1/24") to dev.
// IPv6 addresses skip duplicate address detection so they are usable at once.
func (n *NS) Addr(t testing.TB, dev, cidr string) {
	t.Helper()
	p := netip.MustParsePrefix(cidr)
	a := &netlink.Addr{IPNet: IPNet(p)}
	if p.Addr().Is6() {
		a.Flags = unix.IFA_F_NODAD
	}
	n.Must(t, n.Handle.AddrAdd(n.Link(t, dev), a))
	if p.Addr().Is6() { // its local route appears asynchronously
		want := net.IP(p.Addr().AsSlice())
		n.waitLocalRoute(t, dev, cidr, want.Equal)
	}
}

// Route adds "dst via gw" (gw may be empty for a device route).
func (n *NS) Route(t testing.TB, dst, gw, dev string) {
	t.Helper()
	p := netip.MustParsePrefix(dst)
	r := &netlink.Route{Dst: IPNet(p), LinkIndex: n.Link(t, dev).Attrs().Index}
	if gw != "" {
		r.Gw = net.IP(netip.MustParseAddr(gw).AsSlice())
	} else {
		r.Scope = netlink.SCOPE_LINK
	}
	n.Must(t, n.Handle.RouteAdd(r))
}

// Sysctl sets a per-netns sysctl, e.g. "net.ipv4.ip_forward".
func (n *NS) Sysctl(t testing.TB, key, value string) {
	t.Helper()
	n.Do(t, func() error {
		return os.WriteFile("/proc/sys/"+strings.ReplaceAll(key, ".", "/"), []byte(value), 0o644)
	})
}

// IPNet converts a prefix, keeping host bits (as an interface address needs).
func IPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// RequireWireGuard skips (or fails, under ZORA_REQUIRE_NETNS=1) unless the
// kernel can create WireGuard links.
func RequireWireGuard(t testing.TB) {
	t.Helper()
	n := New(t, "wgprobe")
	err := n.Handle.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wgprobe"}})
	if err != nil {
		skipOrFail(t, fmt.Sprintf("kernel cannot create WireGuard links (is the wireguard module loaded? `sudo modprobe wireguard`): %v", err))
	}
}
