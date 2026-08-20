package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

func TestPostCompactCleanTranscript(t *testing.T) {
	tp := writeTempTranscript(t, "compacted summary: nothing sensitive\n")
	in := `{"session_id":"s1","transcript_path":` + testenv.JSONString(tp) + `,"hook_event_name":"PostCompact"}`
	var out bytes.Buffer
	if err := PostCompact(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean post-compact should passthrough, got %q", got)
	}
}

func TestPostCompactWarnsOnSecretInSummary(t *testing.T) {
	tp := writeTempTranscript(t, "summary: user discussed AWS keys including "+akia+" — be careful\n")
	in := `{"session_id":"s1","transcript_path":` + testenv.JSONString(tp) + `,"hook_event_name":"PostCompact"}`
	var out bytes.Buffer
	if err := PostCompact(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	// PostCompact uses top-level shape per spec; explicitly no decision field.
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Errorf("PostCompact must emit top-level fields, got nested: %q", out.String())
	}
	if _, hasDecision := m["decision"]; hasDecision {
		t.Errorf("PostCompact has no decision field per spec, got: %q", out.String())
	}
	msg, _ := m["systemMessage"].(string)
	for _, want := range []string{"post-compaction", "compromised", "rotating"} {
		if !strings.Contains(msg, want) {
			t.Errorf("systemMessage missing %q: %q", want, msg)
		}
	}
}

func TestPostCompactBadInputFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := PostCompact(strings.NewReader("bogus"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}
