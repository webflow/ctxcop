package claudecode

import (
	"testing"

	"github.com/webflow/ctxcop/internal/skiplist"
)

// TestShouldSkipPathShim is a smoke check that the local shim wired
// into Read/Write handlers calls through to the shared skiplist
// package. Matcher behavior lives in internal/skiplist/skiplist_test.go.
func TestShouldSkipPathShim(t *testing.T) {
	t.Setenv("CTXCOP_SKIP_PATHS", "")
	defer skiplist.ResetForTest()
	if !shouldSkipPath("internal/runner/runner_test.go") {
		t.Errorf("default *_test.* pattern should skip _test.go file")
	}
	if shouldSkipPath("internal/runner/runner.go") {
		t.Errorf("non-test path should not be skipped")
	}
}
