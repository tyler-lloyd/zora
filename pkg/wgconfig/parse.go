package wgconfig

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type section int

const (
	sectionNone section = iota
	sectionInterface
	sectionPeer
)

// hookKeys are wg-quick directives that execute shell commands. zora runs as
// root on the host, so honouring them would hand host root to anyone who can
// write a Secret.
var hookKeys = map[string]string{
	"preup": "PreUp", "postup": "PostUp", "predown": "PreDown", "postdown": "PostDown",
}

type parser struct {
	cfg  Config
	sect section
	line int

	sawInterface  bool
	interfaceLine int
	seen          map[string]int // scalar key -> line, reset per section
	peerLines     []int          // line of each [Peer] header
}

// Parse parses a wg-quick style config.
//
// Matching wg(8), all whitespace is insignificant, '#' starts a comment,
// section names and keys are case-insensitive, and list values (Address,
// AllowedIPs, DNS) may be comma-separated and repeated. Unlike wg(8), Parse is
// strict where silent fix-ups would surprise: it rejects duplicate scalar
// keys, duplicate peers and AllowedIPs claimed by more than one peer.
func Parse(data []byte) (*Config, error) {
	if len(data) > MaxConfigSize {
		return nil, newParseError(0, fmt.Sprintf("config is %d bytes; the limit is %d", len(data), MaxConfigSize))
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // editors on Windows add one
	p := &parser{cfg: Config{Interface: Interface{Table: Table{Mode: TableAuto}}}}
	for raw := range bytes.Lines(data) {
		p.line++
		if err := p.parseLine(string(raw)); err != nil {
			return nil, err
		}
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return &p.cfg, nil
}

func (p *parser) errorf(format string, args ...any) error {
	return newParseError(p.line, fmt.Sprintf(format, args...))
}

// newParseError is the only way this package builds a ParseError. It scrubs
// anything shaped like key material from the message, so no code path (now
// or in a future change) can leak a key that was pasted into the wrong field
// into a pod Event. FuzzParse checks this holds for every input.
func newParseError(line int, msg string) *ParseError {
	return &ParseError{Line: line, Msg: scrubKeyMaterial(msg)}
}

// minScrubRun is the shortest run of base64 characters that is scrubbed.
// Real keys are 44 characters; no legitimate message word is this long
// (the longest, "PersistentKeepalive", is 19).
const minScrubRun = 20

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

// scrubKeyMaterial replaces every run of at least minScrubRun base64
// characters with "[redacted]".
func scrubKeyMaterial(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && isBase64Char(s[j]) {
			j++
		}
		switch {
		case j-i >= minScrubRun:
			b.WriteString("[redacted]")
			i = j
		case j > i:
			b.WriteString(s[i:j])
			i = j
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// normalizeLine applies wg(8)'s lexical rules: drop the comment, then drop
// every ASCII whitespace character.
func normalizeLine(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			return -1
		}
		return r
	}, s)
}

// safeName returns s quoted if it is safe to echo in an error. Only short
// purely alphabetic strings qualify; anything else could be a fragment of a
// mangled key line such as "PrivateKeyAbC123...".
func safeName(s string) string {
	if len(s) == 0 || len(s) > 32 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return ""
		}
	}
	return strconv.Quote(s)
}

func (p *parser) parseLine(raw string) error {
	line := normalizeLine(raw)
	if line == "" {
		return nil
	}
	if line[0] == '[' {
		return p.parseSection(line)
	}
	key, value, ok := strings.Cut(line, "=")
	if !ok || key == "" {
		return p.errorf("expected \"Key = Value\" or a [Section] header")
	}
	switch p.sect {
	case sectionNone:
		return p.errorf("key outside of a section; the config must start with [Interface] or [Peer]")
	case sectionInterface:
		return p.parseInterfaceKey(key, value)
	default:
		return p.parsePeerKey(key, value)
	}
}

func (p *parser) parseSection(line string) error {
	if !strings.HasSuffix(line, "]") {
		return p.errorf("unterminated section header")
	}
	name := line[1 : len(line)-1]
	p.seen = map[string]int{}
	switch strings.ToLower(name) {
	case "interface":
		if p.sawInterface {
			return p.errorf("duplicate [Interface] section (first on line %d)", p.interfaceLine)
		}
		p.sawInterface, p.interfaceLine, p.sect = true, p.line, sectionInterface
	case "peer":
		p.cfg.Peers = append(p.cfg.Peers, Peer{})
		p.peerLines = append(p.peerLines, p.line)
		p.sect = sectionPeer
	default:
		if n := safeName(name); n != "" {
			return p.errorf("unknown section [%s]; expected [Interface] or [Peer]", name)
		}
		return p.errorf("unknown section; expected [Interface] or [Peer]")
	}
	return nil
}

// once rejects a second occurrence of a scalar key in the current section.
func (p *parser) once(canonical string) error {
	if first, dup := p.seen[canonical]; dup {
		return p.errorf("duplicate %s (first on line %d)", canonical, first)
	}
	p.seen[canonical] = p.line
	return nil
}

func (p *parser) parseInterfaceKey(key, value string) error {
	iface := &p.cfg.Interface
	switch lk := strings.ToLower(key); lk {
	case "privatekey":
		if err := p.once("PrivateKey"); err != nil {
			return err
		}
		k, err := ParseSecretKey(value)
		if err != nil {
			return p.errorf("PrivateKey %v", err) // never echo the value
		}
		iface.PrivateKey = k
	case "address":
		return p.eachListItem(value, func(item string) error {
			pfx, err := parsePrefixOrAddr(item)
			if err != nil {
				return p.errorf("Address %q: %v", item, err)
			}
			a := pfx.Addr()
			if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
				return p.errorf("Address %q: must be a unicast address", item)
			}
			for _, existing := range iface.Addresses {
				if existing.Addr() == a {
					return p.errorf("Address %q: duplicate address", item)
				}
			}
			iface.Addresses = append(iface.Addresses, pfx)
			return nil
		})
	case "listenport":
		if err := p.once("ListenPort"); err != nil {
			return err
		}
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return p.errorf("ListenPort %q: must be a number from 0 to 65535", value)
		}
		iface.ListenPort = uint16(n)
	case "fwmark":
		if err := p.once("FwMark"); err != nil {
			return err
		}
		n, err := parseFwMark(value)
		if err != nil {
			return p.errorf("FwMark %q: must be \"off\", a decimal number or a 0x-prefixed hex number below 2^32", value)
		}
		iface.FwMark = n
	case "mtu":
		if err := p.once("MTU"); err != nil {
			return err
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || n < 576 || n > 65535 {
			return p.errorf("MTU %q: must be a number from 576 to 65535", value)
		}
		iface.MTU = int(n)
	case "table":
		if err := p.once("Table"); err != nil {
			return err
		}
		t, err := parseTable(value)
		if err != nil {
			return p.errorf("Table %q: %v", value, err)
		}
		iface.Table = t
	case "dns":
		if len(iface.DNS) == 0 {
			p.cfg.Warnings = append(p.cfg.Warnings, Warning{Line: p.line,
				Message: "DNS is ignored: a pod's resolv.conf is managed by the kubelet; set spec.dnsConfig instead"})
		}
		return p.eachListItem(value, func(item string) error {
			if _, err := netip.ParseAddr(item); err != nil && !validHostname(item) {
				return p.errorf("DNS %q: must be an IP address or a search domain", item)
			}
			iface.DNS = append(iface.DNS, item)
			return nil
		})
	case "saveconfig":
		return p.errorf("SaveConfig is not supported: zora never writes config files")
	default:
		if canonical, isHook := hookKeys[lk]; isHook {
			return p.errorf("%s is not supported: zora never executes hook commands", canonical)
		}
		return p.unknownKey(key, "[Interface]")
	}
	return nil
}

func (p *parser) parsePeerKey(key, value string) error {
	peer := &p.cfg.Peers[len(p.cfg.Peers)-1]
	switch strings.ToLower(key) {
	case "publickey":
		if err := p.once("PublicKey"); err != nil {
			return err
		}
		k, err := ParseKey(value)
		if err != nil {
			return p.errorf("PublicKey %v", err)
		}
		peer.PublicKey = k
	case "presharedkey":
		if err := p.once("PresharedKey"); err != nil {
			return err
		}
		k, err := ParseSecretKey(value)
		if err != nil {
			return p.errorf("PresharedKey %v", err) // never echo the value
		}
		peer.PresharedKey = &k
	case "allowedips":
		return p.eachListItem(value, func(item string) error {
			pfx, err := parsePrefixOrAddr(item)
			if err != nil {
				return p.errorf("AllowedIPs %q: %v", item, err)
			}
			pfx = pfx.Masked()
			for _, existing := range peer.AllowedIPs {
				if existing == pfx {
					return nil // wg(8) merges duplicates within a peer
				}
			}
			peer.AllowedIPs = append(peer.AllowedIPs, pfx)
			return nil
		})
	case "endpoint":
		if err := p.once("Endpoint"); err != nil {
			return err
		}
		ep, err := parseEndpoint(value)
		if err != nil {
			return p.errorf("Endpoint %q: %v", value, err)
		}
		peer.Endpoint = &ep
	case "persistentkeepalive":
		if err := p.once("PersistentKeepalive"); err != nil {
			return err
		}
		if strings.EqualFold(value, "off") {
			peer.PersistentKeepalive = 0
			return nil
		}
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return p.errorf("PersistentKeepalive %q: must be \"off\" or a number of seconds from 0 to 65535", value)
		}
		peer.PersistentKeepalive = uint16(n)
	default:
		return p.unknownKey(key, "[Peer]")
	}
	return nil
}

func (p *parser) unknownKey(key, sect string) error {
	if n := safeName(key); n != "" {
		return p.errorf("unknown key %s in %s", n, sect)
	}
	return p.errorf("unrecognised key in %s", sect)
}

// eachListItem calls fn for each comma-separated item. Empty items, as in a
// trailing comma, are skipped.
func (p *parser) eachListItem(value string, fn func(string) error) error {
	for item := range strings.SplitSeq(value, ",") {
		if item == "" {
			continue
		}
		if err := fn(item); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) finish() error {
	if !p.sawInterface {
		return newParseError(0, "missing [Interface] section")
	}
	iface := &p.cfg.Interface
	if iface.PrivateKey.IsZero() {
		return newParseError(p.interfaceLine, "[Interface] has no PrivateKey")
	}
	self := iface.PrivateKey.PublicKey()

	keyLine := map[Key]int{}
	ipOwner := map[netip.Prefix]int{} // prefix -> header line of the peer claiming it
	for i := range p.cfg.Peers {
		peer, line := &p.cfg.Peers[i], p.peerLines[i]
		if peer.PublicKey.IsZero() {
			return newParseError(line, "[Peer] has no PublicKey")
		}
		if peer.PublicKey == self {
			return newParseError(line, "[Peer] PublicKey is this interface's own public key")
		}
		if first, dup := keyLine[peer.PublicKey]; dup {
			return newParseError(line, fmt.Sprintf("duplicate [Peer] PublicKey (first on line %d)", first))
		}
		keyLine[peer.PublicKey] = line
		for _, pfx := range peer.AllowedIPs {
			if first, dup := ipOwner[pfx]; dup {
				return newParseError(line, fmt.Sprintf(
					"AllowedIPs %s is also claimed by the peer on line %d; WireGuard would silently give it to only one of them", pfx, first))
			}
			ipOwner[pfx] = line
		}
	}
	return nil
}

// parsePrefixOrAddr accepts "addr/bits" or a bare address, which means a
// host prefix (/32 or /128). The host bits of addr/bits are preserved.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("not a valid CIDR")
		}
		if pfx.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 addresses are not supported")
		}
		return pfx, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("not a valid IP address or CIDR")
	}
	if a.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 addresses are not supported")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseFwMark(s string) (uint32, error) {
	if strings.EqualFold(s, "off") {
		return 0, nil
	}
	base, digits := 10, s
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		base, digits = 16, s[2:]
	}
	n, err := strconv.ParseUint(digits, base, 32)
	return uint32(n), err
}

func parseTable(s string) (Table, error) {
	switch strings.ToLower(s) {
	case "auto":
		return Table{Mode: TableAuto}, nil
	case "off":
		return Table{Mode: TableOff}, nil
	case "main":
		return Table{Mode: TableID, ID: MainTable}, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return Table{}, fmt.Errorf("must be \"auto\", \"off\", \"main\" or a table number")
	}
	switch n {
	case 0, 253, 255:
		return Table{}, fmt.Errorf("table %d is reserved by the kernel", n)
	}
	return Table{Mode: TableID, ID: uint32(n)}, nil
}

func parseEndpoint(s string) (Endpoint, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("must be host:port, with IPv6 addresses in brackets")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return Endpoint{}, fmt.Errorf("port must be a number from 1 to 65535")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return Endpoint{}, fmt.Errorf("IPv6 zones are not supported")
		}
		if a.IsUnspecified() || a.IsMulticast() {
			return Endpoint{}, fmt.Errorf("must be a unicast address")
		}
		return Endpoint{Host: a.Unmap().String(), Port: uint16(n)}, nil
	}
	if strings.Contains(host, ":") || !validHostname(host) {
		return Endpoint{}, fmt.Errorf("host must be an IP address or a DNS name")
	}
	return Endpoint{Host: host, Port: uint16(n)}, nil
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// validHostname checks RFC 1123 syntax and rejects names that look like
// mistyped IPv4 addresses (an all-numeric final label).
func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !isAlnum(c) && c != '-' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return true
		}
	}
	return false
}
