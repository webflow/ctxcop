package claudecode

import "github.com/webflow/ctxcop/internal/skiplist"

// shouldSkipPath wraps skiplist.ShouldSkip — local alias to keep handler
// call sites short.
func shouldSkipPath(path string) bool {
	return skiplist.ShouldSkip(path)
}
