// Package golden compares test output against checked-in golden files.
//
// Run `go test ./... -update` to rewrite golden files after an intended
// change, then review the diff like any other code change.
package golden

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files instead of comparing against them")

// Assert compares got with the contents of path, or rewrites path when the
// -update flag is set.
func Assert(t testing.TB, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run `go test -update` to create it): %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("output differs from %s (run `go test -update` if the change is intended)\n%s",
			path, lineDiff(string(want), string(got)))
	}
}

// JSON marshals v the way every golden JSON file is formatted.
func JSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// lineDiff is a minimal line-oriented diff: good enough to spot the change
// without pulling in a diff library.
func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < max(len(w), len(g)); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl == gl {
			continue
		}
		if i < len(w) {
			b.WriteString("- " + wl + "\n")
		}
		if i < len(g) {
			b.WriteString("+ " + gl + "\n")
		}
	}
	return b.String()
}
