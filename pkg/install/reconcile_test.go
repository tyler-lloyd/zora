package install

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const dir = "/etc/cni/net.d"

// memFS is an in-memory FS that records writes, so scenarios can assert
// exactly which files zora touched.
type memFS struct {
	files    map[string][]byte
	writes   []string
	writeErr error
}

func newMemFS(files map[string]string) *memFS {
	m := &memFS{files: map[string][]byte{}}
	for k, v := range files {
		m.files[filepath.Join(dir, k)] = []byte(v)
	}
	return m
}

func (m *memFS) ReadDir(d string) ([]string, error) {
	var out []string
	for p := range m.files {
		if filepath.Dir(p) == d {
			out = append(out, filepath.Base(p))
		}
	}
	return out, nil
}

func (m *memFS) ReadFile(p string) ([]byte, error) {
	b, ok := m.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return slices.Clone(b), nil
}

func (m *memFS) WriteFile(p string, data []byte) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.files[p] = slices.Clone(data)
	m.writes = append(m.writes, filepath.Base(p))
	return nil
}

func (m *memFS) Remove(p string) error {
	if _, ok := m.files[p]; !ok {
		return fs.ErrNotExist
	}
	delete(m.files, p)
	m.writes = append(m.writes, "rm "+filepath.Base(p))
	return nil
}

// put simulates another component writing a file.
func (m *memFS) put(name, data string) { m.files[filepath.Join(dir, name)] = []byte(data) }

func (m *memFS) rename(from, to string) {
	m.files[filepath.Join(dir, to)] = m.files[filepath.Join(dir, from)]
	delete(m.files, filepath.Join(dir, from))
}

func (m *memFS) get(name string) string { return string(m.files[filepath.Join(dir, name)]) }

func (m *memFS) takeWrites() []string {
	w := m.writes
	m.writes = nil
	return w
}

func newReconciler(m *memFS) *Reconciler {
	return &Reconciler{Dir: dir, Entry: testEntry, FS: m}
}

func reconcile(t *testing.T, r *Reconciler) Status {
	t.Helper()
	st, err := r.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return st
}

func fixture(t *testing.T, name string) string { return string(fixtures(t)[name]) }

func TestWaitsForThePrimaryAndNeverWritesItsOwnConfig(t *testing.T) {
	m := newMemFS(map[string]string{"calico-kubeconfig": "apiVersion: v1"})
	r := newReconciler(m)
	for range 3 {
		st := reconcile(t, r)
		if st.Installed || !strings.Contains(st.Reason, "waiting for the primary CNI") {
			t.Fatalf("status = %+v", st)
		}
	}
	if w := m.takeWrites(); len(w) != 0 {
		t.Fatalf("wrote %v with no primary config present", w)
	}

	m.put("10-flannel.conflist", fixture(t, "flannel.conflist")) // the primary arrives
	st := reconcile(t, r)
	if !st.Installed || st.Primary != "10-flannel.conflist" {
		t.Fatalf("status = %+v", st)
	}
	if w := m.takeWrites(); !slices.Equal(w, []string{"10-flannel.conflist"}) {
		t.Fatalf("writes = %v", w)
	}
	if !HasEntry("10-flannel.conflist", []byte(m.get("10-flannel.conflist"))) {
		t.Fatal("zora not chained")
	}
	// Steady state: nothing to do, so no writes (and no fsnotify loop).
	for range 3 {
		reconcile(t, r)
	}
	if w := m.takeWrites(); len(w) != 0 {
		t.Fatalf("steady-state passes wrote %v", w)
	}
}

func TestReinsertsAfterThePrimaryRewritesItsConfig(t *testing.T) {
	// Cilium rewrites its config on every agent start.
	m := newMemFS(map[string]string{"05-cilium.conflist": fixture(t, "cilium.conflist")})
	r := newReconciler(m)
	reconcile(t, r)
	m.takeWrites()
	m.put("05-cilium.conflist", fixture(t, "cilium.conflist"))
	if st := reconcile(t, r); !st.Installed {
		t.Fatalf("status = %+v", st)
	}
	if w := m.takeWrites(); !slices.Equal(w, []string{"05-cilium.conflist"}) {
		t.Fatalf("writes = %v", w)
	}
}

// TestBacksOffWhenAnotherProcessKeepsReverting models Cilium with
// cni.exclusive=true, which regenerates its config on any activity in the
// directory. On a real cluster this was a write loop of ~16 rewrites per
// second between the two daemons.
func TestBacksOffWhenAnotherProcessKeepsReverting(t *testing.T) {
	orig := fixture(t, "cilium.conflist")
	m := newMemFS(map[string]string{"05-cilium.conflist": orig})
	clock := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	r := newReconciler(m)
	r.Now = func() time.Time { return clock }
	guarding := true
	// pass runs one reconcile, then lets the other daemon react.
	pass := func() Status {
		st := reconcile(t, r)
		if guarding {
			m.put("05-cilium.conflist", orig)
		}
		clock = clock.Add(60 * time.Millisecond)
		return st
	}
	writes := func() int { return len(m.takeWrites()) }

	var st Status
	for range 1000 { // a minute of fsnotify-driven passes
		st = pass()
	}
	if n := writes(); n > maxReverts {
		t.Fatalf("%d writes while being reverted; want at most %d before backing off", n, maxReverts)
	}
	if st.Installed || !strings.Contains(st.Reason, "keeps removing zora") || !strings.Contains(st.Reason, "cni.exclusive=false") {
		t.Fatalf("status = %+v; it must say what is happening and how to fix it", st)
	}

	// After the delay it tries once; still reverted, so it waits longer.
	clock = clock.Add(initialBackoff)
	for range 100 { // six seconds
		pass()
	}
	if n := writes(); n != 1 {
		t.Fatalf("%d writes after the first backoff, want exactly one retry", n)
	}
	clock = clock.Add(initialBackoff + time.Second)
	for range 100 {
		pass()
	}
	if n := writes(); n != 0 {
		t.Fatalf("%d writes; the second backoff must be longer than the first", n)
	}

	// The admin fixes the primary's settings: zora gets in and stays.
	guarding = false
	clock = clock.Add(2 * initialBackoff)
	if st = pass(); !st.Installed {
		t.Fatalf("status = %+v", st)
	}
	clock = clock.Add(revertWindow)
	pass()
	// A single rewrite much later (the primary restarting) is not a
	// fight: zora re-inserts at once, with the backoff forgotten.
	m.put("05-cilium.conflist", orig)
	if st = pass(); !st.Installed || r.backoff != 0 {
		t.Fatalf("status = %+v, backoff = %s", st, r.backoff)
	}
}

func TestFollowsANewPrimary(t *testing.T) {
	t.Run("cilium exclusive mode renames the old config", func(t *testing.T) {
		m := newMemFS(map[string]string{"10-flannel.conflist": fixture(t, "flannel.conflist")})
		r := newReconciler(m)
		reconcile(t, r)
		m.takeWrites()
		m.put("05-cilium.conflist", fixture(t, "cilium.conflist"))
		m.rename("10-flannel.conflist", "10-flannel.conflist.cilium_bak")
		st := reconcile(t, r)
		if !st.Installed || st.Primary != "05-cilium.conflist" {
			t.Fatalf("status = %+v", st)
		}
		// The backup is not a config file; zora leaves it alone.
		if w := m.takeWrites(); !slices.Equal(w, []string{"05-cilium.conflist"}) {
			t.Fatalf("writes = %v", w)
		}
	})
	t.Run("old config stays behind", func(t *testing.T) {
		m := newMemFS(map[string]string{"10-flannel.conflist": fixture(t, "flannel.conflist")})
		r := newReconciler(m)
		reconcile(t, r)
		m.takeWrites()
		m.put("05-cilium.conflist", fixture(t, "cilium.conflist"))
		if st := reconcile(t, r); st.Primary != "05-cilium.conflist" {
			t.Fatalf("status = %+v", st)
		}
		if HasEntry("10-flannel.conflist", []byte(m.get("10-flannel.conflist"))) {
			t.Fatal("zora left in a config the runtime no longer reads")
		}
		if w := m.takeWrites(); !slices.Equal(w, []string{"10-flannel.conflist", "05-cilium.conflist"}) {
			t.Fatalf("writes = %v", w)
		}
	})
}

func TestConvertsASingleConf(t *testing.T) {
	m := newMemFS(map[string]string{"10-bridge.conf": fixture(t, "bridge-single.conf")})
	r := newReconciler(m)
	st := reconcile(t, r)
	if !st.Installed || st.Primary != "10-bridge.conflist" {
		t.Fatalf("status = %+v", st)
	}
	if w := m.takeWrites(); !slices.Equal(w, []string{"10-bridge.conflist", "rm 10-bridge.conf"}) {
		t.Fatalf("writes = %v; the .conflist must exist before the .conf is removed", w)
	}
	reconcile(t, r)
	if w := m.takeWrites(); len(w) != 0 {
		t.Fatalf("second pass wrote %v", w)
	}
	// Its owner reinstalls the .conf: zora converges again.
	m.put("10-bridge.conf", fixture(t, "bridge-single.conf"))
	if st := reconcile(t, r); st.Primary != "10-bridge.conflist" || m.get("10-bridge.conf") != "" {
		t.Fatalf("status = %+v, files = %v", st, slices.Collect(maps.Keys(m.files)))
	}
}

func TestLeavesAnInvalidPrimaryAlone(t *testing.T) {
	full := fixture(t, "calico.conflist")
	m := newMemFS(map[string]string{"10-calico.conflist": full[:len(full)/2]}) // mid-write
	r := newReconciler(m)
	st := reconcile(t, r)
	if st.Installed || !strings.Contains(st.Reason, "not usable yet") {
		t.Fatalf("status = %+v", st)
	}
	if w := m.takeWrites(); len(w) != 0 {
		t.Fatalf("wrote %v over an invalid primary", w)
	}
	m.put("10-calico.conflist", full) // the write completes
	if st := reconcile(t, r); !st.Installed {
		t.Fatalf("status = %+v", st)
	}

	// Parseable JSON that the runtime rejects (here: no name). Chaining
	// zora into it would not make it usable, so leave it to its owner.
	broken := `{"cniVersion": "0.3.1", "plugins": [{"type": "flannel"}]}`
	m = newMemFS(map[string]string{"10-flannel.conflist": broken})
	if st := reconcile(t, newReconciler(m)); st.Installed || m.get("10-flannel.conflist") != broken {
		t.Fatalf("status = %+v; file:\n%s", st, m.get("10-flannel.conflist"))
	}
}

// vanishingFS lists a file that is gone by the time it is read, as happens
// when a primary CNI replaces its config by removing and re-creating it.
type vanishingFS struct{ *memFS }

func (v vanishingFS) ReadFile(string) ([]byte, error) { return nil, fs.ErrNotExist }

func TestToleratesThePrimaryVanishingMidPass(t *testing.T) {
	m := newMemFS(map[string]string{"10-flannel.conflist": fixture(t, "flannel.conflist")})
	r := &Reconciler{Dir: dir, Entry: testEntry, FS: vanishingFS{m}}
	st, err := r.Reconcile()
	if err != nil || st.Installed || !strings.Contains(st.Reason, "retrying") {
		t.Fatalf("status = %+v, err = %v; want a quiet retry", st, err)
	}
	if w := m.takeWrites(); len(w) != 0 {
		t.Fatalf("wrote %v", w)
	}
}

func TestIgnoresFilesTheRuntimeIgnores(t *testing.T) {
	m := newMemFS(map[string]string{
		"10-flannel.conflist":            fixture(t, "flannel.conflist"),
		".zora-10-flannel.conflist.tmp":  "{garbage",
		"00-multus.kubeconfig":           "apiVersion: v1",
		"05-cilium.conflist.cilium_bak":  fixture(t, "cilium.conflist"),
		"whereabouts.d/whereabouts.conf": "{}",
	})
	if st := reconcile(t, newReconciler(m)); st.Primary != "10-flannel.conflist" || !st.Installed {
		t.Fatalf("status = %+v", st)
	}
}

func TestUpdatesTheEntryWhenSettingsChange(t *testing.T) {
	m := newMemFS(map[string]string{"10-flannel.conflist": fixture(t, "flannel.conflist")})
	r := newReconciler(m)
	reconcile(t, r)
	r.Entry.ExcludeNamespaces = []string{"kube-system", "monitoring"}
	reconcile(t, r)
	got := m.get("10-flannel.conflist")
	if !strings.Contains(got, "monitoring") || strings.Count(got, `"type": "zora"`) != 1 {
		t.Fatalf("entry not updated in place:\n%s", got)
	}
}

func TestUninstallRestoresTheOriginal(t *testing.T) {
	for name, data := range fixtures(t) {
		if !strings.HasSuffix(name, ".conflist") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			m := newMemFS(map[string]string{"10-x.conflist": string(data)})
			r := newReconciler(m)
			reconcile(t, r)
			wrote, err := r.Uninstall()
			if err != nil || !slices.Equal(wrote, []string{"10-x.conflist"}) {
				t.Fatalf("Uninstall = %v, %v", wrote, err)
			}
			if got := m.get("10-x.conflist"); !jsonEqual(t, got, string(data)) {
				t.Fatalf("uninstall did not restore the original:\n%s", got)
			}
			if wrote, _ := r.Uninstall(); len(wrote) != 0 {
				t.Fatalf("second Uninstall wrote %v", wrote)
			}
		})
	}
}

func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	return slices.Equal([]string{string(mustCompact(t, a))}, []string{string(mustCompact(t, b))})
}

func mustCompact(t *testing.T, s string) []byte {
	t.Helper()
	o, err := parseObject([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	b, err := o.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReconcileReportsWriteErrors(t *testing.T) {
	m := newMemFS(map[string]string{"10-flannel.conflist": fixture(t, "flannel.conflist")})
	m.writeErr = errors.New("read-only file system")
	if _, err := newReconciler(m).Reconcile(); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("err = %v", err)
	}
}

// TestRunOnARealDirectory drives the real watch loop: the primary appears
// with a non-atomic write, is rewritten by its owner, and zora follows.
func TestRunOnARealDirectory(t *testing.T) {
	d := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := Watch(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(chan Status, 100)
	r := &Reconciler{Dir: d, Entry: testEntry, FS: OSFS{}}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		r.Run(ctx, events, nil, func(st Status, err error) {
			if err != nil {
				t.Errorf("reconcile: %v", err)
			}
			statuses <- st
		})
	}()
	// Stop the loop before the temp directory is removed under it.
	defer func() {
		cancel()
		<-stopped
	}()
	waitFor := func(what string, cond func(Status) bool) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case st := <-statuses:
				if cond(st) {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	waitFor("the initial pass", func(st Status) bool { return !st.Installed })

	path := filepath.Join(d, "10-flannel.conflist")
	data := fixtures(t)["flannel.conflist"]
	f, err := os.Create(path) // a non-atomic write, as cp does
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(data[:20])
	time.Sleep(50 * time.Millisecond)
	_, _ = f.Write(data[20:])
	_ = f.Close()
	waitFor("installation", func(st Status) bool { return st.Installed })
	installed, _ := os.ReadFile(path)
	if !HasEntry("10-flannel.conflist", installed) {
		t.Fatalf("not chained:\n%s", installed)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil { // the owner rewrites it
		t.Fatal(err)
	}
	waitFor("re-installation", func(st Status) bool {
		b, _ := os.ReadFile(path)
		return st.Installed && HasEntry("10-flannel.conflist", b)
	})
	entries, _ := os.ReadDir(d)
	for _, e := range entries {
		if isOwnTemp(e.Name()) {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestInstallBinary(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	dst := filepath.Join(d, "bin", "zora")
	if err := os.WriteFile(src, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, want := range []bool{true, false} {
		changed, err := InstallBinary(src, dst)
		if err != nil || changed != want {
			t.Fatalf("install #%d: changed=%v err=%v", i+1, changed, err)
		}
	}
	st, err := os.Stat(dst)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v, %v", st.Mode(), err)
	}
	if err := os.WriteFile(src, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := InstallBinary(src, dst); err != nil || !changed {
		t.Fatalf("upgrade: changed=%v err=%v", changed, err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "v2" {
		t.Fatalf("dst = %q", b)
	}
}

func TestOSFSWriteKeepsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "10-x.conflist")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (OSFS{}).WriteFile(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600 kept", st.Mode().Perm())
	}
}
