package wgconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse checks the parser's contracts on arbitrary input:
//   - it never panics;
//   - every error is a *ParseError whose message contains no key material;
//   - every accepted config survives Encode/Parse unchanged.
//
// The corpus is seeded from every fixture in testdata, so new fixtures
// automatically widen fuzzing. Run with `make fuzz` or
// `go test -fuzz=FuzzParse ./pkg/wgconfig`.
func FuzzParse(f *testing.F) {
	for _, dir := range []string{"valid", "invalid"} {
		files, _ := filepath.Glob(filepath.Join("testdata", dir, "*.conf"))
		for _, path := range files {
			b, err := os.ReadFile(path)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("error is %T, want *ParseError: %v", err, err)
			}
			assertNoKeyMaterial(t, err.Error())
			return
		}
		assertRoundTrip(t, cfg)
	})
}
