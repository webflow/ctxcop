package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSessionStartShape(t *testing.T) {
	var buf bytes.Buffer
	if err := SessionStart(&buf); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, buf.String())
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if hso["hookEventName"] != "SessionStart" {
		t.Errorf("hookEventName=%v", hso["hookEventName"])
	}
	ctx, _ := hso["additionalContext"].(string)
	if ctx == "" {
		t.Fatalf("additionalContext empty")
	}
	for _, expect := range []string{
		"ctxcop",
		"$ENV_VAR",
		"process.env",
		"<REDACTED:",
		"--query",
	} {
		if !strings.Contains(ctx, expect) {
			t.Errorf("priming missing %q\n--full--\n%s", expect, ctx)
		}
	}
}
