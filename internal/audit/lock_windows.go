//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// fileLock is an advisory cross-process lock backed by LockFileEx on a
// sibling lockfile — Windows' equivalent of flock(2) used on unix (see
// lock_unix.go). Hooks run as separate processes, so the in-process
// sync.Mutex isn't enough to serialize the read-Prev + append critical
// section — this closes that gap. The zero value is unusable; obtain
// one via acquireLock.
type fileLock struct {
	f *os.File
}

// acquireLock takes an exclusive advisory lock on path+".lock", blocking
// until it's held. Returns nil (with a no-op release) if the lock can't be
// taken — audit logging is best-effort and must never block or crash a hook.
func acquireLock(path string) *fileLock {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil
	}
	// Lock the entire possible file range (0..MaxUint64), blocking until
	// held — LOCKFILE_EXCLUSIVE_LOCK without LOCKFILE_FAIL_IMMEDIATELY
	// matches flock(2)'s LOCK_EX blocking semantics. The zeroed Overlapped
	// starts the range at byte 0.
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		^uint32(0), ^uint32(0),
		new(windows.Overlapped),
	); err != nil {
		_ = f.Close()
		return nil
	}
	return &fileLock{f: f}
}

// release drops the lock. Safe on a nil receiver so callers can defer it
// unconditionally right after acquireLock.
func (l *fileLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, ^uint32(0), ^uint32(0), new(windows.Overlapped))
	_ = l.f.Close()
}
