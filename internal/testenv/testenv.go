// Package testenv holds small cross-platform test-isolation helpers
// shared by harness install/pause tests. Both helpers here exist
// because of the same underlying problem: a test fixture built with
// only Unix conventions in mind (a $HOME env var, a forward-slash
// path spliced into JSON) silently breaks on Windows instead of
// failing loudly, so the bug surfaces as a confusing panic or a
// mismatched assertion far from its actual cause.
package testenv

import (
	"encoding/json"
	"testing"
)

// SetHomeDir points every OS-specific "home directory" lookup ctxcop's
// production code might make (os.UserHomeDir) at dir for the duration
// of the test. Setting only $HOME is not enough: os.UserHomeDir reads
// %USERPROFILE% on Windows and does not fall back to $HOME at all, so
// a test that only sets HOME silently redirects nothing on that
// platform — Install() then writes to the real Windows user profile
// instead of dir, and any assertion that reads back a hardcoded path
// under dir finds nothing there.
func SetHomeDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// SetTempDir points every OS-specific "temp directory" lookup ctxcop's
// production code might make (os.TempDir) at dir for the duration of
// the test. Setting only $TMPDIR is not enough: os.TempDir reads
// %TMP%, then %TEMP%, then %USERPROFILE% on Windows and never looks at
// $TMPDIR, so a test that only sets TMPDIR silently redirects nothing
// on that platform — production code writes under the real Windows
// temp directory instead of dir, and an assertion built against a
// hardcoded path under dir either finds nothing there or, worse,
// passes vacuously because the (wrong) real path just happens to
// differ from the test's guessed path.
func SetTempDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
}

// JSONString returns s as a valid double-quoted JSON string literal
// (including the surrounding quotes), safe to splice directly into a
// hand-built JSON test fixture. Building a fixture by concatenating a
// raw OS path into a JSON literal is not safe: Windows paths contain
// backslashes, which are JSON escape characters, so the resulting
// literal contains invalid escape sequences (e.g. \U, \A) that fail to
// parse — the hook's json.Unmarshal errors out and the fail-open
// passthrough fires instead of the behavior the test means to exercise.
func JSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal only errors on unsupported types (channels,
		// functions, cyclic values) — never on a plain string.
		panic(err)
	}
	return string(b)
}
