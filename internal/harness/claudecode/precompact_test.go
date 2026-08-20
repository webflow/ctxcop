package claudecode

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

func TestPreCompactCleanTranscript(t *testing.T) {
	tp := writeTempTranscript(t, "hello world\nno secrets here\n")
	in := `{"session_id":"s1","transcript_path":` + testenv.JSONString(tp) + `,"hook_event_name":"PreCompact"}`
	var out bytes.Buffer
	if err := PreCompact(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean transcript should passthrough, got %q", got)
	}
}

func TestPreCompactFlagsSecrets(t *testing.T) {
	tp := writeTempTranscript(t, "log line one\nAWS_KEY="+akia+"\nlog line three\n")
	in := `{"session_id":"s1","transcript_path":` + testenv.JSONString(tp) + `,"hook_event_name":"PreCompact"}`
	var out bytes.Buffer
	if err := PreCompact(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	// PreCompact uses the top-level shape (UserPromptSubmit family), not
	// nested under hookSpecificOutput. If this regresses to nested, the
	// harness won't surface the systemMessage and the warning is silently
	// dropped — exactly the failure mode that bit UserPromptSubmit before.
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Errorf("PreCompact must emit top-level fields, not hookSpecificOutput: %q", out.String())
	}
	msg, _ := m["systemMessage"].(string)
	for _, want := range []string{"compact", "secret-shape", "ctxcop-aws-access-key"} {
		if !strings.Contains(msg, want) {
			t.Errorf("systemMessage missing %q: %q", want, msg)
		}
	}
	if _, hasDecision := m["decision"]; hasDecision {
		t.Errorf("PreCompact must NOT block (compaction is observe-only for ctxcop), got decision in: %q", out.String())
	}
}

func TestPreCompactMissingTranscriptPath(t *testing.T) {
	in := `{"session_id":"s1","hook_event_name":"PreCompact"}`
	var out bytes.Buffer
	if err := PreCompact(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("missing transcript_path should passthrough, got %q", got)
	}
}

func TestPreCompactBadInputFailsOpen(t *testing.T) {
	in := `not json at all`
	var out bytes.Buffer
	if err := PreCompact(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

// writeTempTranscript drops content into a tempfile and returns the path.
// t.TempDir() cleanup handles removal.
func writeTempTranscript(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
