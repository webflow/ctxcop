package claudecode

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SessionEnd cleans up the per-invocation redacted-copy directories that
// Read-interception (claudecode and cursor) create under $TMPDIR/ctxcop/.
// Fail-open.
func SessionEnd(w io.Writer) error {
	dir := filepath.Join(os.TempDir(), "ctxcop")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return passthrough(w)
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		if !looksLikeOurTemp(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) || isFromThisSession(info.ModTime()) {
			// RemoveAll: our temp artifacts are now directories
			// ("redact-<random>/<basename>"), not bare files.
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	_ = os.Remove(dir)
	return passthrough(w)
}

// looksLikeOurTemp matches the per-invocation redacted-copy directories
// created by writeRedactedTemp ("redact-<random>"). The distinctive prefix
// avoids removing unrelated files a user may have stashed under $TMPDIR/ctxcop.
func looksLikeOurTemp(name string) bool {
	return strings.HasPrefix(name, tempSubdirPrefix) && len(name) > len(tempSubdirPrefix)
}

// isFromThisSession is a placeholder for future per-session cleanup logic.
func isFromThisSession(_ time.Time) bool { return true }
