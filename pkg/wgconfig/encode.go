package wgconfig

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
)

// Encode renders c in canonical wg-quick syntax. The output contains the
// private key in the clear.
//
// For any config that Parse accepts, Parse(Encode(c)) equals c apart from
// warning line numbers, and Encode is a fixed point:
// Encode(Parse(Encode(c))) == Encode(c). The fuzz tests enforce both.
func Encode(c *Config) []byte {
	var b bytes.Buffer
	i := c.Interface
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", i.PrivateKey.Base64())
	if len(i.Addresses) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", joinPrefixes(i.Addresses))
	}
	if i.ListenPort != 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", i.ListenPort)
	}
	if i.FwMark != 0 {
		fmt.Fprintf(&b, "FwMark = 0x%x\n", i.FwMark)
	}
	if i.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", i.MTU)
	}
	switch i.Table.Mode {
	case TableOff:
		b.WriteString("Table = off\n")
	case TableID:
		fmt.Fprintf(&b, "Table = %d\n", i.Table.ID)
	}
	if len(i.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(i.DNS, ", "))
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey.Base64())
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", joinPrefixes(p.AllowedIPs))
		}
		if p.Endpoint != nil {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive != 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.Bytes()
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}
