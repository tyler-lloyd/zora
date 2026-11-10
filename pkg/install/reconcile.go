package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"
)

// FS is the filesystem the reconciler works on: the CNI config directory.
type FS interface {
	// ReadDir returns the names of the regular files in dir.
	ReadDir(dir string) ([]string, error)
	ReadFile(path string) ([]byte, error)
	// WriteFile replaces path atomically.
	WriteFile(path string, data []byte) error
	Remove(path string) error
}

// Entry is zora's plugin entry in the conflist.
type Entry struct {
	Socket            string   `json:"socket,omitempty"`
	ExcludeNamespaces []string `json:"excludeNamespaces"`
	TimeoutSeconds    int      `json:"timeoutSeconds,omitempty"`
}

// MarshalJSON renders the conflist entry, declaring the capability under
// which containerd passes pod annotations.
func (e Entry) MarshalJSON() ([]byte, error) {
	type plain Entry
	return json.Marshal(struct {
		Type         string          `json:"type"`
		Capabilities map[string]bool `json:"capabilities"`
		plain
	}{PluginType, map[string]bool{"io.kubernetes.cri.pod-annotations": true}, plain(e)})
}

// Status describes the installation.
type Status struct {
	// Primary is the config file zora is chained into, or would be.
	Primary string `json:"primary,omitempty"`
	// Installed means the runtime's config chains zora.
	Installed bool `json:"installed"`
	// Reason explains why zora is not installed.
	Reason string `json:"reason,omitempty"`
	// Wrote lists files this pass changed.
	Wrote []string `json:"wrote,omitempty"`
}

// Reconciler keeps zora chained into the runtime's CNI config.
type Reconciler struct {
	Dir   string
	Entry Entry
	FS    FS
}

func (r *Reconciler) configFiles() ([]string, error) {
	names, err := r.FS.ReadDir(r.Dir)
	if err != nil {
		return nil, err
	}
	var cfgs []string
	for _, n := range names {
		if IsConfigFile(n) {
			cfgs = append(cfgs, n)
		}
	}
	slices.Sort(cfgs)
	return cfgs, nil
}

// Reconcile makes one pass. It never creates a config of its own, and when
// the primary is missing or invalid it changes nothing.
func (r *Reconciler) Reconcile() (Status, error) {
	entry, err := json.Marshal(r.Entry)
	if err != nil {
		return Status{}, err
	}
	cfgs, err := r.configFiles()
	if err != nil {
		return Status{}, err
	}
	if len(cfgs) == 0 {
		return Status{Reason: fmt.Sprintf("waiting for the primary CNI to write its config to %s", r.Dir)}, nil
	}
	primary := cfgs[0]
	st := Status{Primary: primary}
	data, err := r.FS.ReadFile(filepath.Join(r.Dir, primary))
	if err != nil {
		return st, err
	}
	name, out, err := Chain(primary, data, entry)
	var invalid *InvalidConfigError
	if errors.As(err, &invalid) {
		// Possibly mid-write by its owner; the next event or resync retries.
		st.Reason = fmt.Sprintf("primary CNI config is not usable yet, waiting: %v", err)
		return st, nil
	}
	if err != nil {
		return st, err
	}

	// If the primary changed (another CNI's config now sorts first), take
	// zora out of files the runtime no longer reads.
	for _, other := range cfgs[1:] {
		if other == name {
			continue
		}
		path := filepath.Join(r.Dir, other)
		d, err := r.FS.ReadFile(path)
		if err != nil || !HasEntry(other, d) {
			continue
		}
		if cleaned, changed, err := Unchain(other, d); err == nil && changed {
			if err := r.FS.WriteFile(path, cleaned); err != nil {
				return st, err
			}
			st.Wrote = append(st.Wrote, other)
		}
	}

	if name != primary {
		// Converted .conf: write the .conflist, then remove the .conf. In
		// between, the .conf still sorts first, so the runtime keeps using
		// the unchained original rather than seeing a gap.
		if err := r.FS.WriteFile(filepath.Join(r.Dir, name), out); err != nil {
			return st, err
		}
		if err := r.FS.Remove(filepath.Join(r.Dir, primary)); err != nil {
			return st, err
		}
		st.Wrote = append(st.Wrote, name, primary)
	} else if !bytes.Equal(out, data) {
		if err := r.FS.WriteFile(filepath.Join(r.Dir, name), out); err != nil {
			return st, err
		}
		st.Wrote = append(st.Wrote, name)
	}
	st.Primary, st.Installed = name, true
	return st, nil
}

// Uninstall removes zora from every config file and returns the files it
// changed.
func (r *Reconciler) Uninstall() ([]string, error) {
	cfgs, err := r.configFiles()
	if err != nil {
		return nil, err
	}
	var wrote []string
	var errs []error
	for _, n := range cfgs {
		path := filepath.Join(r.Dir, n)
		d, err := r.FS.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cleaned, changed, err := Unchain(n, d)
		if err != nil || !changed {
			continue
		}
		if err := r.FS.WriteFile(path, cleaned); err != nil {
			errs = append(errs, err)
			continue
		}
		wrote = append(wrote, n)
	}
	return wrote, errors.Join(errs...)
}

// Run reconciles now, on every event, and on every tick, until ctx ends.
// report receives each pass's outcome.
func (r *Reconciler) Run(ctx context.Context, events <-chan struct{}, ticks <-chan time.Time, report func(Status, error)) {
	pass := func() {
		st, err := r.Reconcile()
		report(st, err)
	}
	pass()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				events = nil // watcher gone: keep resyncing on ticks
				continue
			}
			pass()
		case <-ticks:
			pass()
		}
	}
}
