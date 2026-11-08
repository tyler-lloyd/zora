package wgconfig

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/curve25519"
)

// KeyLen is the length in bytes of every WireGuard key.
const KeyLen = 32

// redacted is what secret material renders as in logs, errors and fmt output.
const redacted = "(redacted)"

var (
	errKeyFormat = errors.New("must be a 32-byte base64-encoded key")
	errKeyZero   = errors.New("must not be the all-zero key")
)

// Key is a WireGuard public key. It is not secret and renders as base64.
type Key [KeyLen]byte

// SecretKey holds secret key material: an interface private key or a peer
// preshared key.
//
// Every rendering redacts the value: String, GoString, Format, LogValue and
// MarshalText (so encoding/json and slog's JSON handler redact too). Base64 is
// the only way to reveal it, which keeps every disclosure explicit and
// greppable; code that must send a key over the wire copies Base64 into a
// dedicated wire type.
type SecretKey [KeyLen]byte

func decodeKey(s string) ([KeyLen]byte, error) {
	var k [KeyLen]byte
	if len(s) != base64.StdEncoding.EncodedLen(KeyLen) {
		return k, errKeyFormat
	}
	// Strict rejects non-zero padding bits, so every key has exactly one
	// textual form and parse/encode round-trips byte-for-byte.
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != KeyLen {
		return k, errKeyFormat
	}
	copy(k[:], b)
	if k == [KeyLen]byte{} {
		return k, errKeyZero
	}
	return k, nil
}

// ParseKey decodes a base64 public key.
func ParseKey(s string) (Key, error) {
	k, err := decodeKey(s)
	return Key(k), err
}

// String returns the base64 encoding of the key.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// IsZero reports whether k is the zero value (unset).
func (k Key) IsZero() bool { return k == Key{} }

// MarshalText implements encoding.TextMarshaler.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Key) UnmarshalText(b []byte) error {
	v, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// ParseSecretKey decodes a base64 private or preshared key.
func ParseSecretKey(s string) (SecretKey, error) {
	k, err := decodeKey(s)
	return SecretKey(k), err
}

// Base64 reveals the key. Use only when handing the key to the kernel or wire.
func (k SecretKey) Base64() string { return base64.StdEncoding.EncodeToString(k[:]) }

// IsZero reports whether k is the zero value (unset).
func (k SecretKey) IsZero() bool { return k == SecretKey{} }

// Equal compares two secret keys in constant time.
func (k SecretKey) Equal(o SecretKey) bool { return subtle.ConstantTimeCompare(k[:], o[:]) == 1 }

// Clamped returns the private key as the kernel stores it: Curve25519
// clamping clears the low three bits and sets bit 254. Any 32 bytes are a
// valid WireGuard private key and clamping does not change the public key,
// but reading the key back from the kernel returns the clamped form.
func (k SecretKey) Clamped() SecretKey {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k
}

// PublicKey derives the Curve25519 public key, treating k as a private key.
func (k SecretKey) PublicKey() Key {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// X25519 with the base point only fails for low-order inputs, which
		// cannot happen for the base point.
		panic(fmt.Sprintf("wgconfig: deriving public key: %v", err))
	}
	var out Key
	copy(out[:], pub)
	return out
}

// String redacts the key.
func (SecretKey) String() string { return redacted }

// GoString redacts the key for %#v.
func (SecretKey) GoString() string { return redacted }

// Format redacts the key for every fmt verb, including %x and %d, which would
// otherwise bypass String and print the underlying bytes.
func (SecretKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue redacts the key in slog output.
func (SecretKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler by redacting. There is
// deliberately no UnmarshalText: SecretKey never round-trips through text
// except via ParseSecretKey and Base64.
func (SecretKey) MarshalText() ([]byte, error) { return []byte(redacted), nil }
