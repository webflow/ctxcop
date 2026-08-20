package aider

import (
	"reflect"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/shellwrap"
)

const testSelf = "/usr/local/bin/ctxcop"

func TestSplitLangPrefix(t *testing.T) {
	cases := []struct {
		in      string
		wantLng string
		wantCmd string
		wantOK  bool
	}{
		{"python: ruff check", "python", "ruff check", true},
		{"python:ruff check", "python", "ruff check", true}, // no space required (Aider's actual grammar)
		{"go: golangci-lint run", "go", "golangci-lint run", true},
		{"just-a-command", "", "", false},
		{"cmd:no-space-but-lowercase", "cmd", "no-space-but-lowercase", true},
		{": no-lang", "", "", false},
		{"CI=1 pytest", "", "", false}, // uppercase before ':' isn't Aider's lang grammar
		{"c++: clang-tidy", "", "", false},
	}
	for _, tc := range cases {
		gotLng, gotCmd, gotOK := splitLangPrefix(tc.in)
		if gotOK != tc.wantOK {
			t.Errorf("splitLangPrefix(%q).ok = %v, want %v", tc.in, gotOK, tc.wantOK)
		}
		if !tc.wantOK {
			continue
		}
		if gotLng != tc.wantLng || gotCmd != tc.wantCmd {
			t.Errorf("splitLangPrefix(%q) = (%q,%q), want (%q,%q)",
				tc.in, gotLng, gotCmd, tc.wantLng, tc.wantCmd)
		}
	}
}

func TestWrapEntryRoutesThroughBashC(t *testing.T) {
	wrapped, changed := wrapEntry(testSelf, false, "ruff check")
	if !changed {
		t.Fatal("expected change")
	}
	want := shellwrap.Quote(testSelf) + " run -- bash -c " + shellwrap.Quote("ruff check")
	if wrapped != want {
		t.Errorf("wrapEntry = %q, want %q", wrapped, want)
	}
}

func TestWrapEntryPreservesLanguagePrefix(t *testing.T) {
	wrapped, changed := wrapEntry(testSelf, false, "python: ruff check")
	if !changed {
		t.Fatal("expected change")
	}
	if !strings.HasPrefix(wrapped, "python: ") {
		t.Errorf("language prefix lost: %q", wrapped)
	}
	if !strings.Contains(wrapped, "bash -c") {
		t.Errorf("expected bash -c routing: %q", wrapped)
	}
}

// TestWrapEntryHandlesCompoundAndEnvPrefixedCommands is the regression
// test for Andrew's review: the old bare-prefix wrap
// ("ctxcop run -- <cmd>") only sent the first shell word through
// ctxcop, so "a && b" leaked b's output unredacted, and "CI=1 pytest"
// broke outright (ctxcop's runner execs argv[0] directly with no
// shell, so "CI=1" was treated as a literal, nonexistent binary).
// Routing through `bash -c '<original>'` fixes both: the entire
// original string is a single quoted argument to a real shell.
func TestWrapEntryHandlesCompoundAndEnvPrefixedCommands(t *testing.T) {
	cases := []string{
		"pytest -x && npm test",
		"CI=1 pytest",
		"cd backend && pytest",
	}
	for _, original := range cases {
		wrapped, changed := wrapEntry(testSelf, true, original)
		if !changed {
			t.Fatalf("expected change for %q", original)
		}
		inner, streaming, ok := parseWrap(wrapped, testSelf)
		if !ok {
			t.Fatalf("parseWrap couldn't parse own wrap of %q: %q", original, wrapped)
		}
		if !streaming {
			t.Errorf("expected streaming wrap for %q", original)
		}
		if inner != original {
			t.Errorf("round-trip mismatch: original %q, recovered %q", original, inner)
		}
		if !strings.Contains(wrapped, "bash -c") {
			t.Errorf("expected bash -c in wrap of %q: %q", original, wrapped)
		}
	}
}

// TestWrapEntryUsesResolvedSelfPath is the regression test for
// Andrew's point that the old wrap hardcoded the literal string
// "ctxcop" instead of resolving the binary's actual path — meaning
// PATH differences between install time and Aider's actual shell
// (especially its pexpect path, which sources interactive rc files)
// could silently run a different "ctxcop" or fail to find one at all.
func TestWrapEntryUsesResolvedSelfPath(t *testing.T) {
	self := "/opt/custom/path/ctxcop"
	wrapped, _ := wrapEntry(self, false, "ruff check")
	if !strings.HasPrefix(wrapped, self+" ") {
		t.Errorf("wrap does not lead with resolved self path: %q", wrapped)
	}
}

func TestUnwrapEntryRoundTrip(t *testing.T) {
	cases := []string{
		"ruff check",
		"python: ruff check",
		"pytest -x && npm test",
	}
	for _, original := range cases {
		wrapped, _ := wrapEntry(testSelf, false, original)
		unwrapped, changed := unwrapEntry(testSelf, wrapped)
		if !changed {
			t.Fatalf("expected change unwrapping %q", wrapped)
		}
		if unwrapped != original {
			t.Errorf("round-trip mismatch: original %q, got %q", original, unwrapped)
		}
	}
}

// TestUnwrapEntryDoesNotDropSpace is the regression test for Andrew's
// point #5: the old stripRunPrefix used string concatenation without a
// separating space when a prefix existed before the marker, corrupting
// any prefixed command on uninstall ("CI=1 ctxcop run --stream -- pytest -x"
// unwrapped to "CI=1pytest -x"). The new bash -c design has no
// "prefix before the marker" case at all — the whole original string,
// prefix included, lives inside the quoted bash -c argument — so this
// verifies the class of bug can't recur.
func TestUnwrapEntryDoesNotDropSpace(t *testing.T) {
	original := "CI=1 pytest -x"
	wrapped, _ := wrapEntry(testSelf, true, original)
	unwrapped, changed := unwrapEntry(testSelf, wrapped)
	if !changed {
		t.Fatal("expected change")
	}
	if unwrapped != original {
		t.Errorf("got %q, want %q (no dropped space)", unwrapped, original)
	}
}

func TestWrapEntryIdempotent(t *testing.T) {
	wrapped, _ := wrapEntry(testSelf, false, "ruff check")
	again, changed := wrapEntry(testSelf, false, wrapped)
	if changed {
		t.Errorf("re-wrapping an already-wrapped entry should be a no-op, got %q", again)
	}
	if again != wrapped {
		t.Errorf("re-wrap mutated value: %q -> %q", wrapped, again)
	}
}

// TestParseWrapRejectsLookalikeSubstring is the regression test for
// Andrew's point #4 and Cursor's MEDIUM finding: the old
// containsRunPrefix used strings.Contains, so a repo-committed
// lint-cmd value that merely mentioned the marker text anywhere
// (e.g. a second command joined with &&) was treated as "already
// wrapped" and install silently skipped wrapping it, leaving it to run
// unredacted. parseWrap now requires the self token to sit immediately
// before the marker AND the quoted argument to consume the entire
// rest of the string.
func TestParseWrapRejectsLookalikeSubstring(t *testing.T) {
	cases := []string{
		// Marker text present, but not as a real, fully-formed wrap.
		"echo hi && " + testSelf + " run -- bash -c 'true'",
		testSelf + " run -- bash -c 'true'; rm -rf /",
		"totally-unrelated-command",
		"./malicious-script run -- bash -c 'true'", // self token doesn't match ours
	}
	for _, s := range cases {
		if _, _, ok := parseWrap(s, testSelf); ok {
			t.Errorf("parseWrap incorrectly accepted %q as already-wrapped", s)
		}
	}
}

func TestWrapLintCmdPreservesNonStringListEntries(t *testing.T) {
	// A non-string YAML list entry (e.g. a stray number or map) must
	// survive the rewrite rather than being silently dropped.
	tree := map[string]any{"lint-cmd": []any{"ruff check", 42, "flake8"}}
	changed := wrapLintCmd(tree, testSelf)
	if changed != 2 {
		t.Errorf("expected 2 string entries wrapped, got %d", changed)
	}
	out, ok := tree["lint-cmd"].([]any)
	if !ok || len(out) != 3 {
		t.Fatalf("expected 3-element list preserved, got %#v", tree["lint-cmd"])
	}
	if out[1] != 42 {
		t.Errorf("non-string entry lost: %#v", out[1])
	}
}

func TestWrapLintCmdIdempotentAndPreservesShape(t *testing.T) {
	tree := map[string]any{"lint-cmd": []any{"python: ruff check", "go: golangci-lint run"}}
	changed := wrapLintCmd(tree, testSelf)
	if changed != 2 {
		t.Errorf("expected 2 entries wrapped, got %d", changed)
	}
	// Re-running should wrap nothing.
	changed = wrapLintCmd(tree, testSelf)
	if changed != 0 {
		t.Errorf("expected idempotent re-wrap to change nothing, got %d", changed)
	}
}

func TestUnwrapLintCmdRoundTrip(t *testing.T) {
	original := map[string]any{
		"lint-cmd": []any{"python: ruff check", "go: golangci-lint run"},
	}
	pre, _ := original["lint-cmd"].([]any)
	preCopy := append([]any(nil), pre...)

	wrapLintCmd(original, testSelf)
	unwrapped := unwrapLintCmd(original, testSelf)
	if unwrapped != 2 {
		t.Errorf("expected 2 unwraps, got %d", unwrapped)
	}
	got := normalizeStringList(original["lint-cmd"])
	want := normalizeStringList(preCopy)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch: got %v want %v", got, want)
	}
}

func TestWrapTestCmdString(t *testing.T) {
	tree := map[string]any{"test-cmd": "pytest -x"}
	if !wrapTestCmd(tree, testSelf) {
		t.Fatal("expected wrap to report change")
	}
	got, _ := tree["test-cmd"].(string)
	if !strings.Contains(got, "run --stream") || !strings.Contains(got, "pytest -x") {
		t.Errorf("wrap: %q", got)
	}
	// Second call: idempotent.
	if wrapTestCmd(tree, testSelf) {
		t.Error("second wrap should be a no-op")
	}
}

func TestWrapTestCmdList(t *testing.T) {
	tree := map[string]any{"test-cmd": []any{"pytest", "go test"}}
	if !wrapTestCmd(tree, testSelf) {
		t.Fatal("expected wrap to report change")
	}
	got := normalizeStringList(tree["test-cmd"])
	if len(got) != 2 {
		t.Fatalf("wrap list: %v", got)
	}
	for i, orig := range []string{"pytest", "go test"} {
		inner, streaming, ok := parseWrap(got[i], testSelf)
		if !ok || !streaming || inner != orig {
			t.Errorf("entry %d: got %q, want wrap of %q", i, got[i], orig)
		}
	}
}

func TestUnwrapTestCmd(t *testing.T) {
	tree := map[string]any{"test-cmd": "pytest -x"}
	wrapTestCmd(tree, testSelf)
	if !unwrapTestCmd(tree, testSelf) {
		t.Fatal("expected unwrap to report change")
	}
	got, _ := tree["test-cmd"].(string)
	if got != "pytest -x" {
		t.Errorf("unwrap: %q", got)
	}
}
