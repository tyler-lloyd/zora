// Package nsutil runs code inside a network namespace identified by path,
// the way a CNI plugin receives it (CNI_NETNS).
package nsutil

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Open opens the network namespace at path, checking that it really is one.
func Open(path string) (*os.File, error) {
	f, err := os.Open(path) // #nosec G304 -- path is a netns handed to us by the runtime
	if err != nil {
		return nil, err
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil { // #nosec G115 -- fds fit in int
		_ = f.Close()
		return nil, fmt.Errorf("statfs %s: %w", path, err)
	}
	// Bind-mounted netns files are on nsfs; /proc/<pid>/ns/net and
	// /proc/<pid>/fd/<n> links resolve to nsfs (or procfs on old kernels).
	if st.Type != unix.NSFS_MAGIC && st.Type != unix.PROC_SUPER_MAGIC {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a network namespace", path)
	}
	return f, nil
}

// Do runs fn on an OS thread that has been switched into the network
// namespace at path. Sockets fn creates belong to that namespace and stay
// there, so they may be used from any goroutine afterwards.
//
// fn must not start goroutines that expect to run in the namespace: only the
// calling goroutine's thread is switched.
func Do(path string, fn func() error) error {
	target, err := Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = target.Close() }()
	return DoFd(target, fn)
}

// DoFd is Do for an already-open namespace.
func DoFd(target *os.File, fn func() error) error {
	errCh := make(chan error, 1)
	// A fresh goroutine guarantees a thread with no surprising state; if we
	// cannot switch it back we leave it locked, and Go destroys the thread
	// when the goroutine exits rather than reusing it in the wrong netns.
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("opening current netns: %w", err)
			return
		}
		defer func() { _ = orig.Close() }()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil { // #nosec G115
			runtime.UnlockOSThread()
			errCh <- fmt.Errorf("entering netns: %w", err)
			return
		}
		fnErr := fn()
		if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil { // #nosec G115
			errCh <- errors.Join(fnErr, fmt.Errorf("leaving netns: %w", err))
			return // thread stays locked and is discarded
		}
		runtime.UnlockOSThread()
		errCh <- fnErr
	}()
	return <-errCh
}
