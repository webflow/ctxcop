//go:build unix

package audit

import (
	"os"
	"syscall"
)

// fileLock is an advisory cross-process lock backed by flock(2) on a sibling
// lockfile. Hooks run as separate processes, so the in-process sync.Mutex
// isn't enough to serialize the read-Prev + append critical section — this
// closes that gap. The zero value is unusable; obtain one via acquireLock.
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
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
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
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}
