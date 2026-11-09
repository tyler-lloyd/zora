package testns

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// DebugDump returns the namespace's network state as ip(8) and wg(8) print
// it, for failure messages. Missing tools are skipped.
func DebugDump(ns *NS) string {
	var b strings.Builder
	for _, args := range [][]string{
		{"ip", "-d", "link"}, {"ip", "addr"}, {"ip", "rule"}, {"ip", "-6", "rule"},
		{"ip", "route", "show", "table", "all"}, {"ip", "-6", "route", "show", "table", "all"},
		{"wg", "show", "all"}, {"sysctl", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.src_valid_mark"},
	} {
		cmd := exec.Command("nsenter", append([]string{"--net=" + ns.Path, "--"}, args...)...)
		out, err := cmd.CombinedOutput()
		if errors.Is(err, exec.ErrNotFound) {
			continue
		}
		fmt.Fprintf(&b, "--- %s: %s\n%s", ns.Name, strings.Join(args, " "), out)
	}
	return b.String()
}

// ServeWhoami listens on addr inside ns and answers every connection with
// the client's source address, so tests can tell tunnelled traffic (source
// = tunnel address) from traffic that took another path.
func ServeWhoami(t testing.TB, ns *NS, addr string) {
	t.Helper()
	var l net.Listener
	ns.Do(t, func() (err error) {
		l, err = net.Listen("tcp", addr)
		return err
	})
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			_, _ = fmt.Fprintln(c, host)
			_ = c.Close()
		}
	}()
}

// Whoami connects from ns to addr (optionally from local) and returns the
// source address the server saw.
func Whoami(t testing.TB, ns *NS, addr, local string) (string, error) {
	t.Helper()
	var reply string
	var dialErr error
	ns.Do(t, func() error {
		d := net.Dialer{Timeout: 3 * time.Second}
		if local != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
		}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			dialErr = err
			return nil
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		reply, err = bufio.NewReader(c).ReadString('\n')
		dialErr = err
		return nil
	})
	return strings.TrimSpace(reply), dialErr
}

// MustWhoami fails the test unless a connection from ns to addr succeeds
// and the server saw wantSource as the client address.
func MustWhoami(t testing.TB, ns *NS, addr, local, wantSource, why string) {
	t.Helper()
	got, err := Whoami(t, ns, addr, local)
	if err != nil {
		t.Fatalf("%s: connecting from %s to %s: %v\n%s", why, ns.Name, addr, err, DebugDump(ns))
	}
	if got != wantSource {
		t.Fatalf("%s: server %s saw source %s, want %s\n%s", why, addr, got, wantSource, DebugDump(ns))
	}
}

// MustNotConnect fails the test if a connection from ns to addr succeeds.
func MustNotConnect(t testing.TB, ns *NS, addr, why string) {
	t.Helper()
	got, err := Whoami(t, ns, addr, "")
	if err == nil {
		t.Fatalf("%s: connection from %s to %s succeeded (server saw %s); it must fail", why, ns.Name, addr, got)
	}
	var errno unix.Errno
	if !errors.As(err, &errno) && !strings.Contains(err.Error(), "timeout") {
		t.Logf("%s: connection failed as required: %v", why, err)
	}
}
