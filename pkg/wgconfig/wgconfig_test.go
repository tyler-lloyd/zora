package wgconfig

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/tyler-lloyd/zora/internal/golden"
)

// Keys used by the fixtures in testdata. They are SHA-256 hashes of short
// strings, not real keys.
const (
	testIfaceKey = "KZKC22QUVCRS52irjCHVv2MX/QI/lHAsVKW1m1J/s9U="
	testPeer1Key = "aYdQoJuTQzd0bwlzRIFn82TK4TLi+LMnrkkT5bVEUCk="
	testPSK      = "Iz7fpYyEhHcS6RFXJTOQfcRnccKvAizqB2a0ItRPMeU="
)

func fixtures(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", dir, "*.conf"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures in testdata/%s: %v", dir, err)
	}
	return files
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestValidFixtures parses every testdata/valid/*.conf and compares the
// result with its .json golden file. To add a case, drop in a .conf file and
// run `go test -update`.
func TestValidFixtures(t *testing.T) {
	for _, path := range fixtures(t, "valid") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := Parse(readFile(t, path))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			golden.Assert(t, strings.TrimSuffix(path, ".conf")+".json", golden.JSON(t, cfg))
			assertRoundTrip(t, cfg)
		})
	}
}

// TestInvalidFixtures checks that every testdata/invalid/*.conf is rejected
// with the error recorded in its .err golden file.
func TestInvalidFixtures(t *testing.T) {
	for _, path := range fixtures(t, "invalid") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := Parse(readFile(t, path))
			if err == nil {
				t.Fatalf("Parse accepted an invalid config: %+v", cfg)
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("error is %T, want *ParseError", err)
			}
			assertNoKeyMaterial(t, err.Error())
			golden.Assert(t, strings.TrimSuffix(path, ".conf")+".err", []byte(err.Error()+"\n"))
		})
	}
}

// assertRoundTrip checks the Encode contract: Parse(Encode(c)) == c (ignoring
// warnings) and Encode is a fixed point.
func assertRoundTrip(t testing.TB, cfg *Config) {
	t.Helper()
	enc := Encode(cfg)
	again, err := Parse(enc)
	if err != nil {
		t.Fatalf("Parse(Encode(cfg)) failed: %v\n%s", err, enc)
	}
	a, b := *cfg, *again
	a.Warnings, b.Warnings = nil, nil
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round trip changed the config\nbefore: %#v\nafter:  %#v\nencoded:\n%s", a, b, enc)
	}
	if enc2 := Encode(again); !bytes.Equal(enc, enc2) {
		t.Fatalf("Encode is not a fixed point\nfirst:\n%s\nsecond:\n%s", enc, enc2)
	}
}

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/=]{20,}`)

// assertNoKeyMaterial enforces the ParseError contract.
func assertNoKeyMaterial(t testing.TB, msg string) {
	t.Helper()
	if m := base64Run.FindString(msg); m != "" {
		t.Fatalf("error message may contain key material %q: %s", m, msg)
	}
}

// TestErrorsNeverLeakKeys feeds lines in which a secret key has been mangled
// or misplaced, so the parser cannot know it is a key, and checks that no
// fragment of the key appears in the error.
func TestErrorsNeverLeakKeys(t *testing.T) {
	const hdr = "[Interface]\nPrivateKey = " + testIfaceKey + "\n"
	cases := map[string]string{
		"missing equals":        "[Interface]\nPrivateKey " + testIfaceKey + "\n",
		"key typo":              "[Interface]\nPrivteKey = " + testIfaceKey + "\n",
		"truncated key":         "[Interface]\nPrivateKey = " + testIfaceKey[:40] + "\n",
		"extra char":            "[Interface]\nPrivateKey = " + testIfaceKey + "x\n",
		"key alone":             "[Interface]\n" + testIfaceKey + "\n",
		"key as section":        "[" + testIfaceKey + "]\n",
		"key in address":        hdr + "Address = " + testPSK + "\n",
		"key in dns":            hdr + "DNS = " + testPSK + "\n",
		"key in endpoint":       hdr + "[Peer]\nPublicKey = " + testPeer1Key + "\nEndpoint = " + testPSK + "\n",
		"key in endpoint host":  hdr + "[Peer]\nPublicKey = " + testPeer1Key + "\nEndpoint = " + testPSK + ":1\n",
		"key in allowedips":     hdr + "[Peer]\nPublicKey = " + testPeer1Key + "\nAllowedIPs = " + testPSK + "\n",
		"key in listenport":     hdr + "ListenPort = " + testPSK + "\n",
		"key in table":          hdr + "Table = " + testPSK + "\n",
		"psk mangled":           hdr + "[Peer]\nPublicKey = " + testPeer1Key + "\nPresharedKey = " + testPSK[:43] + "\n",
		"key outside section":   testIfaceKey + "=" + testPSK + "\n",
		"key as key name":       "[Interface]\n" + testPSK[:30] + "=1\n",
		"duplicate private key": hdr + "PrivateKey = " + testPSK + "\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(input))
			if err == nil {
				t.Fatal("Parse succeeded; the case no longer exercises an error path")
			}
			for _, secret := range []string{testIfaceKey, testPSK} {
				for i := 0; i+8 <= len(secret); i++ {
					if strings.Contains(err.Error(), secret[i:i+8]) {
						t.Fatalf("error leaks key fragment %q: %v", secret[i:i+8], err)
					}
				}
			}
			assertNoKeyMaterial(t, err.Error())
		})
	}
}

func TestSecretKeyRedaction(t *testing.T) {
	cfg, err := Parse(readFile(t, "testdata/valid/vpn-provider-dualstack.conf"))
	if err != nil {
		t.Fatal(err)
	}
	priv := cfg.Interface.PrivateKey
	psk := cfg.Peers[0].PresharedKey
	forbidden := []string{
		priv.Base64(), psk.Base64(),
		hex.EncodeToString(priv[:]), hex.EncodeToString(psk[:]),
		fmt.Sprint([32]byte(priv)), // the decimal byte list
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("cfg", "cfg", cfg, "key", priv, "psk", psk)
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("cfg", "cfg", cfg, "key", priv, "psk", psk)

	outputs := map[string]string{"slog": logBuf.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q"} {
		outputs[verb+" key"] = fmt.Sprintf(verb, priv)
		outputs[verb+" *key"] = fmt.Sprintf(verb, psk)
		outputs[verb+" config"] = fmt.Sprintf(verb, cfg)
		outputs[verb+" *config"] = fmt.Sprintf(verb, *cfg)
	}
	for name, out := range outputs {
		for _, f := range forbidden {
			if strings.Contains(out, f) {
				t.Errorf("%s output reveals a secret key: %s", name, out)
			}
		}
	}
	if got := fmt.Sprint(priv); got != redacted {
		t.Errorf("fmt.Sprint(key) = %q, want %q", got, redacted)
	}
}

func TestPublicKeyDerivation(t *testing.T) {
	// RFC 7748 section 6.1 test vector (Alice).
	privHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	pubHex := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	var priv SecretKey
	b, _ := hex.DecodeString(privHex)
	copy(priv[:], b)
	pub := priv.PublicKey()
	if got := hex.EncodeToString(pub[:]); got != pubHex {
		t.Fatalf("PublicKey() = %s, want %s", got, pubHex)
	}
}

func TestPeerWithOwnPublicKeyRejected(t *testing.T) {
	priv, err := ParseSecretKey(testIfaceKey)
	if err != nil {
		t.Fatal(err)
	}
	input := fmt.Sprintf("[Interface]\nPrivateKey = %s\n[Peer]\nPublicKey = %s\n", testIfaceKey, priv.PublicKey())
	_, err = Parse([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "own public key") {
		t.Fatalf("Parse() error = %v, want own-public-key rejection", err)
	}
}

func TestLineEndingsAndBOM(t *testing.T) {
	lf := readFile(t, "testdata/valid/mesh.conf")
	want, err := Parse(lf)
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string][]byte{
		"crlf":            bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n")),
		"bom":             append([]byte("\xef\xbb\xbf"), lf...),
		"no final eol":    bytes.TrimSuffix(lf, []byte("\n")),
		"bom crlf":        append([]byte("\xef\xbb\xbf"), bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))...),
		"trailing spaces": bytes.ReplaceAll(lf, []byte("\n"), []byte("  \t\n")),
	}
	for name, input := range variants {
		t.Run(name, func(t *testing.T) {
			got, err := Parse(input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v\nwant %#v", got, want)
			}
		})
	}
}

func TestMaxConfigSize(t *testing.T) {
	big := make([]byte, MaxConfigSize+1)
	for i := range big {
		big[i] = '#'
	}
	if _, err := Parse(big); err == nil {
		t.Fatal("Parse accepted an oversized config")
	}
	if _, err := Parse(big[:MaxConfigSize]); err == nil || !strings.Contains(err.Error(), "missing [Interface]") {
		t.Fatalf("a config at exactly the limit should be parsed; got %v", err)
	}
}

func TestEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		literal  bool
		addr     string
		rendered string
	}{
		{"198.51.100.1:51820", "198.51.100.1", true, "198.51.100.1", "198.51.100.1:51820"},
		{"[2001:db8::1]:51820", "2001:db8::1", true, "2001:db8::1", "[2001:db8::1]:51820"},
		{"[::ffff:198.51.100.1]:1", "198.51.100.1", true, "198.51.100.1", "198.51.100.1:1"},
		{"vpn.example.com:443", "vpn.example.com", false, "", "vpn.example.com:443"},
		{"wg.vpn.svc.cluster.local:51820", "wg.vpn.svc.cluster.local", false, "", "wg.vpn.svc.cluster.local:51820"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			ep, err := parseEndpoint(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if ep.Host != c.host || ep.String() != c.rendered {
				t.Fatalf("got host %q rendered %q", ep.Host, ep.String())
			}
			a, ok := ep.Addr()
			if ok != c.literal || (ok && a != netip.MustParseAddr(c.addr)) {
				t.Fatalf("Addr() = %v, %v", a, ok)
			}
		})
	}
}

func TestValidHostname(t *testing.T) {
	good := []string{"a", "example.com", "example.com.", "a-b.c", "x1.y2", "localhost", "1.2.3.example"}
	bad := []string{"", ".", "-a.com", "a-.com", "a..b", "a_b.com", "1.2.3", "1.2.3.4", strings.Repeat("a", 64) + ".com"}
	for _, h := range good {
		if !validHostname(h) {
			t.Errorf("validHostname(%q) = false, want true", h)
		}
	}
	for _, h := range bad {
		if validHostname(h) {
			t.Errorf("validHostname(%q) = true, want false", h)
		}
	}
}

func TestScrubKeyMaterial(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"plain words":                     "plain words",
		"PersistentKeepalive bad":         "PersistentKeepalive bad",
		`Address "` + testPSK + `": x`:    `Address "[redacted]": x`,
		"a" + strings.Repeat("b", 19):     "[redacted]",
		strings.Repeat("b", 19) + " tail": strings.Repeat("b", 19) + " tail",
	}
	for in, want := range cases {
		if got := scrubKeyMaterial(in); got != want {
			t.Errorf("scrubKeyMaterial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClampedKeepsPublicKey(t *testing.T) {
	k, err := ParseSecretKey(testIfaceKey) // a hash, so not pre-clamped
	if err != nil {
		t.Fatal(err)
	}
	c := k.Clamped()
	if c.Equal(k) {
		t.Fatal("fixture key is already clamped; the test needs an unclamped one")
	}
	if c.PublicKey() != k.PublicKey() {
		t.Fatal("clamping changed the public key")
	}
	if !c.Clamped().Equal(c) {
		t.Fatal("Clamped is not idempotent")
	}
}

func TestKeyMethods(t *testing.T) {
	var pub Key
	if err := pub.UnmarshalText([]byte(testPeer1Key)); err != nil || pub.String() != testPeer1Key {
		t.Fatalf("Key.UnmarshalText round trip: %v, %s", err, pub)
	}
	if err := pub.UnmarshalText([]byte("bogus")); err == nil {
		t.Fatal("Key.UnmarshalText accepted garbage")
	}
	a, _ := ParseSecretKey(testIfaceKey)
	b, _ := ParseSecretKey(testPSK)
	if !a.Equal(a) || a.Equal(b) {
		t.Fatal("SecretKey.Equal is wrong")
	}
	if a.String() != redacted || a.GoString() != redacted {
		t.Fatal("SecretKey String/GoString must redact")
	}
	if _, err := ParseKey(testIfaceKey[:43] + "A"); err == nil {
		t.Fatal("ParseKey accepted a key with non-zero padding bits")
	}
}
