package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestPostToolUseScansPlainTextResponse guards H1: previously, when
// tool_response wasn't valid JSON (e.g. a tool returned a quoted
// plain-text blob), Claude Code's PostToolUse silently passed through
// without scanning — a leak path the Codex equivalent already guarded
// against. With the raw-string fallback, plain-text responses get
// scanned and the notice surfaces.
func TestPostToolUseScansPlainTextResponse(t *testing.T) {
	t.Setenv("CTXCOP_POSTTOOLUSE_ALLOW", "")
	t.Setenv("CTXCOP_POSTTOOLUSE", "")
	// tool_response field is a quoted JSON string (valid JSON), but the
	// payload's value is plain text not further-nested JSON. Older code
	// fell through json.Unmarshal as a string and then FirstHit didn't
	// fire because we hadn't yet swapped scan-targets. Cover both
	// shapes: an invalid-JSON byte stream and a JSON string wrapping
	// plain text.
	cases := []string{
		// Case 1: tool_response is a JSON string with plain text inside.
		`{"tool_name":"WebFetch","tool_response":"raw output AccessKey=` + akia + ` trailing"}`,
		// Case 2: tool_response is an array of strings (valid JSON,
		// but the secret is in array element, exercised by FirstHit).
		`{"tool_name":"WebFetch","tool_response":["AccessKey=` + akia + `"]}`,
	}
	for _, in := range cases {
		var out bytes.Buffer
		if err := PostToolUse(strings.NewReader(in), &out); err != nil {
			t.Fatalf("PostToolUse: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("decode: %v (%q)", err, out.String())
		}
		hso, _ := m["hookSpecificOutput"].(map[string]any)
		ctx, _ := hso["additionalContext"].(string)
		if !strings.Contains(ctx, "notice") {
			t.Errorf("plain-text PostToolUse leak not flagged: input=%q output=%q", in, out.String())
		}
	}
}

func TestPostToolUseWarnsOnWebFetchLeak(t *testing.T) {
	t.Setenv("CTXCOP_POSTTOOLUSE_ALLOW", "")
	t.Setenv("CTXCOP_POSTTOOLUSE", "")
	in := `{"tool_name":"WebFetch","tool_response":{"content":"page returned: AccessKey=` + akia + ` end"}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	ctx, _ := hso["additionalContext"].(string)
	for _, want := range []string{"notice", "WebFetch", "handle the value with care", "rotate"} {
		if !strings.Contains(ctx, want) {
			t.Errorf("notice missing %q: %q", want, ctx)
		}
	}
	if strings.Contains(ctx, "WARNING") || strings.Contains(ctx, "compromised") {
		t.Errorf("notice should not use alarmist wording: %q", ctx)
	}
}

// TestPostToolUseRedactsToolOutput guards the updatedToolOutput upgrade:
// Claude Code's PostToolUse can now mutate tool_response (docs at
// code.claude.com/docs/en/hooks), so ctxcop should splice a placeholder
// into the value it hands back, not just warn about it.
func TestPostToolUseRedactsToolOutput(t *testing.T) {
	t.Setenv("CTXCOP_POSTTOOLUSE_ALLOW", "")
	t.Setenv("CTXCOP_POSTTOOLUSE", "")
	in := `{"tool_name":"WebFetch","tool_response":{"content":"page returned: AccessKey=` + akia + ` end"}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	updated, ok := hso["updatedToolOutput"].(map[string]any)
	if !ok {
		t.Fatalf("expected updatedToolOutput object, got %v (%q)", hso["updatedToolOutput"], out.String())
	}
	content, _ := updated["content"].(string)
	if strings.Contains(content, akia) {
		t.Errorf("updatedToolOutput still contains the literal secret: %q", content)
	}
	if !strings.Contains(content, "REDACTED") {
		t.Errorf("updatedToolOutput missing REDACTED placeholder: %q", content)
	}
}

// TestPostToolUseAllowlistDoesNotRewriteOutput: allowlisted tools (e.g.
// intentional secret-store reads) get passthrough with no mutation —
// redacting those would break the workflow the allowlist exists for.
func TestPostToolUseAllowlistDoesNotRewriteOutput(t *testing.T) {
	t.Setenv("CTXCOP_POSTTOOLUSE", "")
	t.Setenv("CTXCOP_POSTTOOLUSE_ALLOW", "mcp__vault__*")
	in := `{"tool_name":"mcp__vault__read_secret","tool_response":{"data":{"password":"` + akia + `"}}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough (no rewrite) for allowlisted tool, got %q", got)
	}
}

func TestPostToolUseDisabled(t *testing.T) {
	t.Setenv("CTXCOP_POSTTOOLUSE", "off")
	in := `{"tool_name":"WebFetch","tool_response":{"content":"AccessKey=` + akia + `"}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough when off, got %q", got)
	}
}

func TestPostToolUseAllowlistSuppresses(t *testing.T) {
	t.Setenv("CTXCOP_POSTTOOLUSE", "")
	t.Setenv("CTXCOP_POSTTOOLUSE_ALLOW", "mcp__vault__*, mcp__1password__*")
	in := `{"tool_name":"mcp__vault__read_secret","tool_response":{"data":{"password":"` + akia + `"}}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough for allowlisted tool, got %q", got)
	}
}

func TestPostToolUseAllowlistDoesNotMatchSiblings(t *testing.T) {
	t.Setenv("CTXCOP_POSTTOOLUSE", "")
	t.Setenv("CTXCOP_POSTTOOLUSE_ALLOW", "mcp__vault__*")
	in := `{"tool_name":"mcp__slack__history","tool_response":{"messages":[{"text":"old creds: ` + akia + `"}]}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) == "{}" {
		t.Errorf("expected warning for non-allowlisted sibling, got passthrough")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"mcp__vault__*", "mcp__vault__read_secret", true},
		{"mcp__vault__*", "mcp__slack__history", false},
		{"*secret*", "mcp__aws__get_secret_value", true},
		{"mcp__*__read_*", "mcp__vault__read_secret", true},
		{"mcp__*__read_*", "mcp__vault__write_secret", false},
		{"exact", "exact", true},
		{"exact", "exacto", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pat, c.s, got, c.want)
		}
	}
}

func TestPostToolUseSkipsBash(t *testing.T) {
	// Bash output is already redacted upstream by PreToolUse rewrite.
	in := `{"tool_name":"Bash","tool_response":{"stdout":"AccessKey=` + akia + `"}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough for Bash, got %q", got)
	}
}

func TestPostToolUseSkipsRead(t *testing.T) {
	in := `{"tool_name":"Read","tool_response":{"content":"file content with ` + akia + `"}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough for Read, got %q", got)
	}
}

func TestPostToolUseCleanResponsePasses(t *testing.T) {
	in := `{"tool_name":"WebFetch","tool_response":{"content":"the cat sat on the mat"}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestPostToolUseWarnsOnNestedMCPLeak(t *testing.T) {
	in := `{"tool_name":"mcp__slack__history","tool_response":{"messages":[{"text":"old creds: ` + akia + `"}]}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	ctx, _ := hso["additionalContext"].(string)
	if !strings.Contains(ctx, "mcp__slack__history") {
		t.Errorf("missing tool name: %q", ctx)
	}
	if !strings.Contains(ctx, "messages[0].text") {
		t.Errorf("missing JSON path: %q", ctx)
	}
}
