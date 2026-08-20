package cursor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/skiplist"
	"github.com/webflow/ctxcop/internal/testenv"
)

// TestCursorReadHonorsSkipList guards H2: previously, Cursor's
// redirectIfReadHasSecret didn't consult the project skip-list at all,
// so a developer's fixture file with intentional credential-shaped
// values was silently redirected to a redacted temp copy and the agent
// saw <REDACTED:...> placeholders instead of the real fixture content.
// With the shared skiplist wired in, Read of a skip-listed path
// passes through unmodified.
func TestCursorReadHonorsSkipList(t *testing.T) {
	defer skiplist.ResetForTest()
	tmp := t.TempDir()
	fixturePath := filepath.Join(tmp, "testdata", "creds.txt")
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, []byte("AKIA"+"LALEMEL33243OLIA"), 0o600); err != nil {
		t.Fatal(err)
	}

	in := `{"tool_name":"Read","tool_input":{"file_path":` + testenv.JSONString(fixturePath) + `}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "{}" {
		t.Errorf("Read of testdata/ path should passthrough, got %q", out.String())
	}
}

// TestCursorWriteHonorsSkipList guards the parallel Write path. A
// developer saving an intentional fixture credential into testdata/
// should be allowed through, not blocked with a deny+user_message.
func TestCursorWriteHonorsSkipList(t *testing.T) {
	defer skiplist.ResetForTest()
	in := `{"tool_name":"Write","tool_input":{"file_path":"src/testdata/creds.txt","content":"AKIA` + "LALEMEL33243OLIA" + `"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "{}" {
		t.Errorf("Write to testdata/ path should passthrough, got %q", out.String())
	}
}
