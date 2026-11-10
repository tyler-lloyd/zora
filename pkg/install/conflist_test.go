package install

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/containernetworking/cni/libcni"

	"github.com/tyler-lloyd/zora/internal/golden"
)

var testEntry = Entry{Socket: "/var/run/zora/zora.sock", ExcludeNamespaces: []string{"kube-system"}}

func entryJSON(t testing.TB, e Entry) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtures(t testing.TB) map[string][]byte {
	t.Helper()
	paths, _ := filepath.Glob("testdata/primaries/*")
	if len(paths) == 0 {
		t.Fatal("no fixtures in testdata/primaries")
	}
	out := map[string][]byte{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = b
	}
	return out
}

func decode(t testing.TB, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return v
}

// pluginType reads a plugin's type the way libcni does (encoding/json
// matches keys case-insensitively, so "tYpe" counts).
func pluginType(p any) string {
	b, _ := json.Marshal(p)
	var v struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(b, &v)
	return v.Type
}

func pluginList(t testing.TB, name string, data []byte) []any {
	t.Helper()
	if filepath.Ext(name) != ".conflist" {
		return []any{decode(t, data)}
	}
	return decode(t, data).(map[string]any)["plugins"].([]any)
}

// checkChained asserts the contract of Chain's output for input data.
func checkChained(t testing.TB, name string, data []byte, outName string, out, entry []byte) {
	t.Helper()
	// The runtime must accept it.
	list, err := libcni.ConfListFromBytes(out)
	if err != nil {
		t.Fatalf("libcni rejects the output: %v\n%s", err, out)
	}
	// Idempotent.
	againName, again, err := Chain(outName, out, entry)
	if err != nil || againName != outName || string(again) != string(out) {
		t.Fatalf("Chain is not idempotent (err %v)\nfirst:\n%s\nsecond:\n%s", err, out, again)
	}
	// Exactly one zora entry, equal to ours; every original plugin kept,
	// in order, with the primary still first.
	orig := pluginList(t, name, data)
	got := pluginList(t, outName, out)
	var others []any
	zoras := 0
	for _, p := range got {
		if pluginType(p) == PluginType {
			zoras++
			if !reflect.DeepEqual(p, decode(t, entry)) {
				t.Fatalf("zora entry %v, want %s", p, entry)
			}
		} else {
			others = append(others, p)
		}
	}
	var origOthers []any
	for _, p := range orig {
		if pluginType(p) != PluginType {
			origOthers = append(origOthers, p)
		}
	}
	if zoras != 1 || !reflect.DeepEqual(others, origOthers) || !reflect.DeepEqual(got[0], orig[0]) {
		t.Fatalf("plugins changed:\nbefore %v\nafter  %v", orig, got)
	}
	// Name and version unchanged.
	in := decode(t, data).(map[string]any)
	wantName, _ := in["name"].(string)
	wantVersion, _ := in["cniVersion"].(string)
	if list.Name != wantName || list.CNIVersion != wantVersion {
		t.Fatalf("name/version %q/%q, want %q/%q", list.Name, list.CNIVersion, wantName, wantVersion)
	}
	// Top-level key order preserved (conflists only; a .conf becomes a
	// new object).
	if filepath.Ext(name) == ".conflist" {
		a, _ := parseObject(data)
		b, _ := parseObject(out)
		if !slices.Equal(a.keys(), b.keys()) {
			t.Fatalf("key order changed: %v -> %v", a.keys(), b.keys())
		}
	}
	// Unchain restores the original plugins.
	restored, changed, err := Unchain(outName, out)
	if err != nil || !changed {
		t.Fatalf("Unchain: changed=%v err=%v", changed, err)
	}
	if HasEntry(outName, restored) || !reflect.DeepEqual(pluginList(t, outName, restored), origOthers) {
		t.Fatalf("Unchain(Chain(x)) != x:\n%s", restored)
	}
	if filepath.Ext(name) == ".conflist" && len(origOthers) == len(orig) && !reflect.DeepEqual(decode(t, restored), decode(t, data)) {
		t.Fatalf("Unchain(Chain(x)) differs from x:\n%s\nvs\n%s", restored, data)
	}
}

// TestChainFixtures chains zora into every fixture, compares with golden
// files and checks the contract. To cover another CNI, drop its config in
// testdata/primaries and run `go test -update`.
func TestChainFixtures(t *testing.T) {
	entry := entryJSON(t, testEntry)
	for name, data := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			outName, out, err := Chain(name, data, entry)
			if err != nil {
				t.Fatal(err)
			}
			golden.Assert(t, filepath.Join("testdata", "chained", outName), out)
			checkChained(t, name, data, outName, out, entry)
		})
	}
}

func TestChainUpdatesInPlace(t *testing.T) {
	data := fixtures(t)["istio-chained.conflist"]
	_, chained, err := Chain("x.conflist", data, entryJSON(t, testEntry))
	if err != nil {
		t.Fatal(err)
	}
	// Someone (Istio's installer, say) appends after us.
	var obj map[string]any
	_ = json.Unmarshal(chained, &obj)
	obj["plugins"] = append(obj["plugins"].([]any), map[string]any{"type": "tuning"})
	after, _ := json.Marshal(obj)

	changed := testEntry
	changed.Socket = "/run/zora/other.sock"
	_, out, err := Chain("x.conflist", after, entryJSON(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, p := range pluginList(t, "x.conflist", out) {
		types = append(types, pluginType(p))
	}
	if want := []string{"calico", "portmap", "istio-cni", "zora", "tuning"}; !slices.Equal(types, want) {
		t.Fatalf("plugin order %v, want %v: zora must keep its slot, not fight for the last one", types, want)
	}
	if !strings.Contains(string(out), "/run/zora/other.sock") {
		t.Fatal("entry was not updated")
	}
}

func TestChainCollapsesDuplicates(t *testing.T) {
	data := []byte(`{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"bridge"},{"type":"zora","socket":"a"},{"type":"portmap"},{"type":"zora","socket":"b"}]}`)
	_, out, err := Chain("n.conflist", data, entryJSON(t, testEntry))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), `"type": "zora"`); n != 1 {
		t.Fatalf("%d zora entries:\n%s", n, out)
	}
}

func TestChainRejects(t *testing.T) {
	entry := entryJSON(t, testEntry)
	cases := map[string]struct{ name, data string }{
		"zora first":           {"a.conflist", `{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"zora"},{"type":"bridge"}]}`},
		"only zora":            {"a.conf", `{"cniVersion":"1.0.0","name":"n","type":"zora"}`},
		"truncated":            {"a.conflist", `{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"bri`},
		"empty plugins":        {"a.conflist", `{"cniVersion":"1.0.0","name":"n","plugins":[]}`},
		"no plugins":           {"a.conflist", `{"cniVersion":"1.0.0","name":"n"}`},
		"conf without type":    {"a.conf", `{"cniVersion":"1.0.0","name":"n"}`},
		"list in a .conf file": {"a.conf", `{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"bridge"}]}`},
		"trailing garbage":     {"a.conflist", `{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"bridge"}]} x`},
		// Valid JSON the runtime still rejects: zora must not "fix" it.
		"no name":             {"a.conflist", `{"cniVersion":"1.0.0","plugins":[{"type":"bridge"}]}`},
		"plugin without type": {"a.conflist", `{"cniVersion":"1.0.0","name":"n","plugins":[{"name":"x"}]}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := Chain(c.name, []byte(c.data), entry)
			var invalid *InvalidConfigError
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v, want *InvalidConfigError", err)
			}
		})
	}
	if _, _, err := Chain("a.conflist", fixtures(t)["flannel.conflist"], []byte(`{"type":"bridge"}`)); err == nil {
		t.Fatal("accepted an entry that isn't zora's")
	}
}

func TestPrimarySelection(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"10-flannel.conflist", "05-cilium.conflist"}, "05-cilium.conflist"},
		{[]string{"10-flannel.conflist.cilium_bak", "99-loopback.conf"}, "99-loopback.conf"},
		{[]string{"10-a.conflist", "10-a.conf"}, "10-a.conf"},
		{[]string{".zora-05-a.conflist.tmp", "10-b.json"}, "10-b.json"},
		{[]string{"README", "calico-kubeconfig", "multus.d"}, ""},
	}
	for _, c := range cases {
		got, ok := Primary(c.names)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("Primary(%v) = %q, %v; want %q", c.names, got, ok, c.want)
		}
	}
}

// FuzzChain checks Chain's contract on arbitrary conflists: it never
// panics, and whatever it accepts it chains correctly.
func FuzzChain(f *testing.F) {
	for _, d := range fixtures(f) {
		f.Add(d)
	}
	f.Add([]byte(`{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"a"},{"type":"zora"},{"type":"zora"}]}`))
	entry := entryJSON(f, testEntry)
	f.Fuzz(func(t *testing.T, data []byte) {
		outName, out, err := Chain("fuzz.conflist", data, entry)
		if err != nil {
			return
		}
		checkChained(t, "fuzz.conflist", data, outName, out, entry)
	})
}
