package plan

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tyler-lloyd/zora/internal/golden"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

const (
	testIfaceKey = "KZKC22QUVCRS52irjCHVv2MX/QI/lHAsVKW1m1J/s9U="
	testPeer1Key = "aYdQoJuTQzd0bwlzRIFn82TK4TLi+LMnrkkT5bVEUCk="
)

func mustParse(t testing.TB, conf string) *wgconfig.Config {
	t.Helper()
	cfg, err := wgconfig.Parse([]byte(conf))
	if err != nil {
		t.Fatalf("wgconfig.Parse: %v", err)
	}
	return cfg
}

// TestGolden computes the plan for each testdata/<case>/{wg.conf,input.json}
// and compares it with testdata/<case>/plan.json. To add a case, create the
// two input files and run `go test -update`.
func TestGolden(t *testing.T) {
	dirs, _ := filepath.Glob("testdata/*/wg.conf")
	if len(dirs) == 0 {
		t.Fatal("no golden cases found")
	}
	for _, confPath := range dirs {
		dir := filepath.Dir(confPath)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			conf, err := os.ReadFile(confPath)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "input.json"))
			if err != nil {
				t.Fatal(err)
			}
			var in Input
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&in); err != nil {
				t.Fatalf("input.json: %v", err)
			}
			in.Config = mustParse(t, string(conf))
			p, err := Compute(in)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			golden.Assert(t, filepath.Join(dir, "plan.json"), golden.JSON(t, p))
			checkInvariants(t, in, p)
		})
	}
}

func TestComputeErrors(t *testing.T) {
	const hdr = "[Interface]\nPrivateKey = " + testIfaceKey + "\n"
	const peer = "[Peer]\nPublicKey = " + testPeer1Key + "\n"
	cluster := ClusterInfo{
		PodCIDRs:     []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16")},
		ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")},
		NodeIPs:      []netip.Addr{netip.MustParseAddr("172.18.0.2")},
	}
	cases := []struct {
		name string
		conf string
		in   Input
		want string
	}{
		{"no peers", hdr, Input{}, "no [Peer] sections"},
		{"table id", hdr + "Table = 1234\n" + peer, Input{}, "Table=1234 is not supported"},
		{"table main", hdr + "Table = main\n" + peer, Input{}, "Table=254 is not supported"},
		{"address in pod cidr", hdr + "Address = 10.244.3.4/32\n" + peer, Input{Cluster: cluster}, "overlaps cluster range 10.244.0.0/16"},
		{"address subnet covers service cidr", hdr + "Address = 10.0.0.2/8\n" + peer, Input{Cluster: cluster}, "overlaps cluster range 10.96.0.0/12"},
		{"address is node ip", hdr + "Address = 172.18.0.2/32\n" + peer, Input{Cluster: cluster}, "overlaps cluster range 172.18.0.2/32"},
		{"unresolved endpoint", hdr + peer + "Endpoint = vpn.example.com:51820\n", Input{}, `endpoint host "vpn.example.com" has not been resolved`},
		{"v6 endpoint without v6", hdr + peer + "Endpoint = [2001:db8::1]:51820\n", Input{IPv6Disabled: true}, "IPv6 is disabled"},
		{"endpoint in own subnet", hdr + "Address = 10.10.0.2/24\n" + peer + "Endpoint = 10.10.0.1:51820\n", Input{}, "would loop"},
		{"ifname too long", hdr + peer, Input{IfName: "wireguard-tunnel0"}, "must be 1-15 characters"},
		{"ifname bad chars", hdr + peer, Input{IfName: "wg/0"}, "may only contain"},
		{"ifname reserved prefix", hdr + peer, Input{IfName: "zw-abc"}, "reserved by zora"},
		{"ifname is uplink", hdr + peer, Input{IfName: "eth0"}, "collides"},
		{"ifname is lo", hdr + peer, Input{IfName: "lo"}, "collides"},
		{"host mode without container id", hdr + peer, Input{Mode: ModeHost}, "requires a container ID"},
		{"unknown mode", hdr + peer, Input{Mode: "sideways"}, "unknown mode"},
		{"tiny uplink", hdr + peer, Input{UplinkMTU: 600}, "too small"},
		{"v6 with small mtu", hdr + "Address = fd00::2/128\n" + peer, Input{UplinkMTU: 1300}, "below the IPv6 minimum"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.in.Config = mustParse(t, c.conf)
			p, err := Compute(c.in)
			if err == nil {
				t.Fatalf("Compute succeeded, want error containing %q; plan: %+v", c.want, p)
			}
			var pe *Error
			if !errors.As(err, &pe) {
				t.Fatalf("error is %T, want *plan.Error", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestComputeDoesNotAliasConfig(t *testing.T) {
	cfg := mustParse(t, "[Interface]\nPrivateKey = "+testIfaceKey+"\n[Peer]\nPublicKey = "+testPeer1Key+"\nAllowedIPs = 10.1.0.0/16\n")
	p, err := Compute(Input{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	p.Device.Peers[0].AllowedIPs[0] = netip.MustParsePrefix("0.0.0.0/0")
	if got := cfg.Peers[0].AllowedIPs[0].String(); got != "10.1.0.0/16" {
		t.Fatalf("mutating the plan changed the config: %s", got)
	}
}

func TestHostBirthNameIsStableAndUnique(t *testing.T) {
	cfg := mustParse(t, "[Interface]\nPrivateKey = "+testIfaceKey+"\n[Peer]\nPublicKey = "+testPeer1Key+"\n")
	name := func(id string) string {
		p, err := Compute(Input{Config: cfg, Mode: ModeHost, ContainerID: id})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Link.BirthName) > MaxIfNameLen {
			t.Fatalf("birth name %q is longer than %d", p.Link.BirthName, MaxIfNameLen)
		}
		return p.Link.BirthName
	}
	if first, second := name("a"), name("a"); first != second {
		t.Fatal("birth name is not deterministic")
	}
	if name("a") == name("b") {
		t.Fatal("different containers got the same birth name")
	}
}

func TestComputeIsDeterministic(t *testing.T) {
	cfg := mustParse(t, "[Interface]\nPrivateKey = "+testIfaceKey+
		"\nAddress = 100.64.0.2/32, fd00::2/128\n[Peer]\nPublicKey = "+testPeer1Key+
		"\nAllowedIPs = ::/0, 10.0.0.0/8, 0.0.0.0/0, 192.168.0.0/16, fd00:1::/64\n")
	in := Input{Config: cfg, Cluster: ClusterInfo{
		ServiceCIDRs: []netip.Prefix{netip.MustParsePrefix("fd00:96::/112"), netip.MustParsePrefix("10.96.0.0/12")},
		NodeIPs:      []netip.Addr{netip.MustParseAddr("172.18.0.2"), netip.MustParseAddr("172.18.0.2")},
	}}
	first, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := Compute(in)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatal("Compute returned different plans for the same input")
		}
	}
}
