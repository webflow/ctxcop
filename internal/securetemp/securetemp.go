// Package securetemp resolves ctxcop's shared temp parent under a check that
// the current user controls it.
package securetemp

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DirName is the shared parent under os.TempDir(). SessionEnd sweeps it for
// per-invocation subdirectories, so it has to stay a single known path.
const DirName = "ctxcop"

// Dir returns a fresh per-invocation directory for redacted copies.
//
// It prefers the shared parent so SessionEnd can sweep it, but falls back to an
// unpredictable directory directly under os.TempDir() when that parent fails
// validation. The fallback matters: callers treat an error here as "skip the
// redaction" and pass the ORIGINAL file through, so failing closed on a hostile
// parent would hand the agent the raw secret — strictly worse than the
// redirection #82 is about. The fallback name is random, so it can't be
// pre-planted.
func Dir(pattern string) (string, error) {
	if parent, err := Parent(); err == nil {
		return os.MkdirTemp(parent, pattern)
	}
	return os.MkdirTemp("", DirName+"-"+pattern)
}

// Parent returns the validated shared parent, creating it if absent.
//
// The redacted copies written beneath it are the plaintext-minus-secrets view
// of files the agent read, so a parent another user controls redirects them.
// os.MkdirAll would silently accept a pre-planted symlink; os.Mkdir plus an
// Lstat rejects one. (#82)
func Parent() (string, error) {
	parent := filepath.Join(os.TempDir(), DirName)
	if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	fi, err := os.Lstat(parent)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("securetemp: %s is a symlink; refusing to write redacted copies through it", parent)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("securetemp: %s is not a directory", parent)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return "", fmt.Errorf("securetemp: %s is writable by group or other (%#o)", parent, perm)
	}
	if err := checkOwner(parent, fi); err != nil {
		return "", err
	}
	return parent, nil
}
