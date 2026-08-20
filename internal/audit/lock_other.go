//go:build !unix && !windows

package audit

// On platforms without flock(2) or LockFileEx (see lock_unix.go and
// lock_windows.go), audit logging degrades to the in-process mutex
// only. ctxcop's supported hook environments (linux, macos, windows)
// are covered by those two files; this keeps the package buildable on
// anything else (plan9, wasm, ...) without a new dependency.
type fileLock struct{}

func acquireLock(string) *fileLock { return nil }

func (l *fileLock) release() {}
