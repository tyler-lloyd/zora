package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

// Contention limits. Some primaries rewrite their config once, when they
// start; zora re-inserts itself and that is the end of it. Others guard the
// file continuously (Cilium with cni.exclusive=true regenerates it on any
// activity in the directory) and would revert zora forever. Re-inserting
// each time would be a tight write loop between two daemons, so after a few
// quick reverts zora stops and retries with a growing delay.
const (
	// revertWindow: losing the entry this soon after writing it counts as
	// being reverted rather than as an unrelated rewrite.
	revertWindow = 10 * time.Second
	// maxReverts quick reverts in a row trigger a backoff.
	maxReverts     = 3
	initialBackoff = time.Minute
	maxBackoff     = 30 * time.Minute
)

// Reconciler keeps zora chained into the runtime's CNI config. It is not
// safe for concurrent use.
type Reconciler struct {
	Dir   string
	Entry Entry
	FS    FS
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	lastWrite time.Time // when we last wrote the primary
	reverts   int       // quick reverts in a row
	backoff   time.Duration
	retryAt   time.Time // no writes to the primary before this
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// contested decides whether a needed write to the primary must wait. It
// returns a reason when it must.
func (r *Reconciler) contested(primary string) string {
	now := r.now()
	if now.Before(r.retryAt) {
		return r.contestedReason(primary)
	}
	if !r.lastWrite.IsZero() && now.Sub(r.lastWrite) < revertWindow {
		r.reverts++
	} else if !r.retryAt.IsZero() {
		// The retry after a backoff: one more revert backs off again.
		r.reverts = maxReverts - 1
		r.retryAt = time.Time{}
	} else {
		r.reverts = 0
	}
	if r.reverts < maxReverts {
		return ""
	}
	if r.backoff == 0 {
		r.backoff = initialBackoff
	} else {
		r.backoff = min(r.backoff*2, maxBackoff)
	}
	r.retryAt = now.Add(r.backoff)
	return r.contestedReason(primary)
}

func (r *Reconciler) contestedReason(primary string) string {
	return fmt.Sprintf("something keeps removing zora from %s right after it is added, so zora has stopped re-adding it until %s; "+
		"if the primary CNI is Cilium, set cni.exclusive=false so it stops reverting changes to its config",
		primary, r.retryAt.UTC().Format(time.RFC3339))
}

// settled notes that the primary needed no write. Once the entry has
// survived the revert window, the contention state is cleared.
func (r *Reconciler) settled() {
	if r.lastWrite.IsZero() || r.now().Sub(r.lastWrite) >= revertWindow {
		r.reverts, r.backoff, r.retryAt = 0, 0, time.Time{}
	}
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
	if errors.Is(err, fs.ErrNotExist) {
		// Removed between listing and reading: its owner is replacing
		// it. The next event or resync sees the result.
		st.Reason = fmt.Sprintf("%s changed while it was being read, retrying", primary)
		return st, nil
	}
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

	needsWrite := name != primary || !bytes.Equal(out, data)
	if !needsWrite {
		r.settled()
	} else if reason := r.contested(primary); reason != "" {
		st.Reason = reason
		return st, nil
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
	} else if needsWrite {
		if err := r.FS.WriteFile(filepath.Join(r.Dir, name), out); err != nil {
			return st, err
		}
		st.Wrote = append(st.Wrote, name)
	}
	if needsWrite {
		r.lastWrite = r.now()
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
