// Package plantest loads pkg/plan's golden cases for other packages' tests,
// so every routing scenario added there is automatically exercised by the
// wire protocol, the kernel tests and the plugin integration tests.
package plantest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tyler-lloyd/zora/pkg/plan"
	"github.com/tyler-lloyd/zora/pkg/wgconfig"
)

// Case is one golden scenario: its input and computed plan.
type Case struct {
	Name  string
	Input plan.Input
	Plan  *plan.Plan
}

// testdataDir locates pkg/plan/testdata relative to this file, so callers
// in any package find it.
func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "pkg", "plan", "testdata")
}

// Cases loads and computes every golden case.
func Cases(t testing.TB) []Case {
	t.Helper()
	confs, _ := filepath.Glob(filepath.Join(testdataDir(), "*", "wg.conf"))
	if len(confs) == 0 {
		t.Fatalf("no golden cases found in %s", testdataDir())
	}
	var out []Case
	for _, confPath := range confs {
		dir := filepath.Dir(confPath)
		conf, err := os.ReadFile(confPath)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "input.json"))
		if err != nil {
			t.Fatal(err)
		}
		var in plan.Input
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if in.Config, err = wgconfig.Parse(conf); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		p, err := plan.Compute(in)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		out = append(out, Case{Name: filepath.Base(dir), Input: in, Plan: p})
	}
	return out
}
