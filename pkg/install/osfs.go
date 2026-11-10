package install

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// OSFS is the real filesystem.
type OSFS struct{}

// ReadDir implements FS.
func (OSFS) ReadDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() || e.Type()&fs.ModeSymlink != 0 {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// ReadFile implements FS.
func (OSFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) } // #nosec G304 -- the CNI config dir

// Remove implements FS.
func (OSFS) Remove(path string) error { return os.Remove(path) }

// WriteFile implements FS: it writes a temp file the runtime ignores, syncs
// it, and renames it over path, keeping path's permissions if it exists.
func (OSFS) WriteFile(path string, data []byte) error {
	return writeAtomic(path, data, 0o644)
}

func writeAtomic(path string, data []byte, defaultMode os.FileMode) (err error) {
	mode := defaultMode
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, tempPrefix+filepath.Base(path)+tempSuffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) // #nosec G304 -- derived from path
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil { // OpenFile's mode is subject to umask
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync() // make the rename durable
}

// InstallBinary copies src to dst atomically, unless dst already has the
// same content. The rename means a runtime exec'ing the old binary keeps
// running it, and never sees a partial file ("text file busy" can't occur).
func InstallBinary(src, dst string) (changed bool, err error) {
	want, err := os.ReadFile(src) // #nosec G304 -- our own binary
	if err != nil {
		return false, err
	}
	if have, err := os.ReadFile(dst); err == nil && sha256.Sum256(have) == sha256.Sum256(want) { // #nosec G304
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- the CNI bin dir is world-readable
		return false, err
	}
	if err := writeAtomic(dst, want, 0o755); err != nil {
		return false, err
	}
	// Executable even if an older dst had other permissions.
	return true, os.Chmod(dst, 0o755) // #nosec G302 -- binaries must be executable
}

// Watch reports changes in dir on the returned channel, coalesced: a burst
// of events produces at least one notification, never a backlog. The
// channel closes when ctx ends or the watcher fails.
func Watch(ctx context.Context, dir string) (<-chan struct{}, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("watching %s: %w", dir, err)
	}
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		defer func() { _ = w.Close() }()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if isOwnTemp(ev.Name) {
					continue
				}
				select {
				case out <- struct{}{}:
				default: // a notification is already pending
				}
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
				// An overflow loses events; a notification makes the
				// reconciler re-read everything.
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out, nil
}

func isOwnTemp(path string) bool {
	b := filepath.Base(path)
	return len(b) > len(tempPrefix)+len(tempSuffix) &&
		b[:len(tempPrefix)] == tempPrefix && b[len(b)-len(tempSuffix):] == tempSuffix
}
