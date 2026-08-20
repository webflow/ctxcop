package cursor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/testenv"
)

func init() { audit.Disable() }

const akia = "AKIA" + "LALEMEL33243OLIA"

// ---- SessionStart ----------------------------------------------------------

func TestSessionStartEmitsAdditionalContext(t *testing.T) {
	var out bytes.Buffer
	if err := SessionStart(&out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	ctx, _ := m["additional_context"].(string)
	for _, want := range []string{
		"ctxcop is active in this Cursor session",
		"WebSearch and AskQuestion bypass", // Cursor-specific caveat
		"updated_mcp_tool_output",          // explains the mechanism
	} {
		if !strings.Contains(ctx, want) {
			t.Errorf("priming missing %q: %q", want, ctx)
		}
	}
}

// ---- beforeSubmitPrompt ----------------------------------------------------

func TestBeforeSubmitPromptBlocksOnSecret(t *testing.T) {
	in := `{"prompt":"please use AWS key ` + akia + `"}`
	var out bytes.Buffer
	if err := BeforeSubmitPrompt(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	// Cursor's beforeSubmitPrompt uses flat shape: continue + user_message.
	cont, ok := m["continue"].(bool)
	if !ok || cont {
		t.Errorf("expected continue=false, got %v", m["continue"])
	}
	msg, _ := m["user_message"].(string)
	if !strings.Contains(msg, "ctxcop-aws-access-key") {
		t.Errorf("user_message missing rule name: %q", msg)
	}
}

func TestBeforeSubmitPromptCleanPasses(t *testing.T) {
	in := `{"prompt":"hello"}`
	var out bytes.Buffer
	if err := BeforeSubmitPrompt(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean prompt should passthrough, got %q", got)
	}
}

// ---- preToolUse -------------------------------------------------------------

func TestPreToolUseDeniesShellWithSecret(t *testing.T) {
	in := `{"tool_name":"Shell","tool_input":{"command":"export KEY=` + akia + `"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Cursor's flat preToolUse output: permission + user_message.
	// We deliberately use the flat (Cursor-native) shape, not the
	// Claude-Code-compat nested hookSpecificOutput shape.
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Errorf("Cursor preToolUse should emit flat permission/user_message, got nested: %q", out.String())
	}
	if got, _ := m["permission"].(string); got != "deny" {
		t.Errorf("permission should be deny, got %q", got)
	}
	msg, _ := m["user_message"].(string)
	for _, want := range []string{"$AWS_TOKEN", "ctxcop-aws-access-key", "env var"} {
		if !strings.Contains(msg, want) {
			t.Errorf("user_message missing %q: %q", want, msg)
		}
	}
}

func TestPreToolUseAllowsCleanShell(t *testing.T) {
	in := `{"tool_name":"Shell","tool_input":{"command":"ls"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean Shell should passthrough, got %q", got)
	}
}

func TestPreToolUseDeniesWriteWithSecret(t *testing.T) {
	in := `{"tool_name":"Write","tool_input":{"file_path":"/tmp/x.go","content":"const k = \"` + akia + `\""}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, _ := m["permission"].(string); got != "deny" {
		t.Errorf("Write with cred should be denied, got %v", m)
	}
	msg, _ := m["user_message"].(string)
	if !strings.Contains(msg, "/tmp/x.go") {
		t.Errorf("user_message should name the file: %q", msg)
	}
}

func TestPreToolUseDeniesMCPWithSecret(t *testing.T) {
	in := `{"tool_name":"MCP:slack:post","tool_input":{"channel":"#general","text":"share ` + akia + `"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, _ := m["permission"].(string); got != "deny" {
		t.Errorf("MCP with cred should be denied, got %v", m)
	}
}

func TestPreToolUsePassthroughUnrelatedTools(t *testing.T) {
	// Grep, Delete, Task are not gated in v0.2.0 — lower-risk surfaces;
	// add later if needed. Read IS gated now (regression: v0.2.0-rc.3
	// shipped without Read gating and Cursor was observed feeding
	// credential-bearing files to the model verbatim because
	// postToolUse.updated_mcp_tool_output is unreliable for built-ins).
	for _, name := range []string{"Grep", "Delete", "Task"} {
		in := `{"tool_name":"` + name + `","tool_input":{"file_path":"/x","query":"` + akia + `"}}`
		var out bytes.Buffer
		if err := PreToolUse(strings.NewReader(in), &out); err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(out.String()); got != "{}" {
			t.Errorf("%s should passthrough, got %q", name, got)
		}
	}
}

func TestPreToolUseRedirectsReadWithSecret(t *testing.T) {
	// Cursor's Read tool with a credential-bearing file must be
	// redirected to a temp file containing redacted content.
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(src, []byte("AWS_KEY="+akia+"\nplain line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := `{"tool_name":"Read","tool_input":{"file_path":` + testenv.JSONString(src) + `}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	if got, _ := m["permission"].(string); got != "allow" {
		t.Errorf("permission should be allow (redirect, not deny), got %q", got)
	}
	updated, _ := m["updated_input"].(map[string]any)
	if updated == nil {
		t.Fatalf("missing updated_input: %q", out.String())
	}
	newPath, _ := updated["file_path"].(string)
	if newPath == "" || newPath == src {
		t.Errorf("file_path should be rewritten to a temp copy, got %q (original was %q)", newPath, src)
	}
	// Verify the temp file actually contains redacted content (not the
	// original secret), so a downstream Cursor that honors updated_input
	// would see placeholders.
	tmp, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("temp file unreadable at %s: %v", newPath, err)
	}
	if strings.Contains(string(tmp), akia) {
		t.Errorf("redacted temp file still contains literal secret: %q", string(tmp))
	}
	if !strings.Contains(string(tmp), "<REDACTED:") {
		t.Errorf("redacted temp file missing placeholder: %q", string(tmp))
	}
	if !strings.Contains(string(tmp), "plain line") {
		t.Errorf("non-secret content damaged: %q", string(tmp))
	}
	// User message surfaces what happened.
	msg, _ := m["user_message"].(string)
	if !strings.Contains(msg, "ctxcop-aws-access-key") {
		t.Errorf("user_message should name the rule: %q", msg)
	}
}

func TestPreToolUseReadCleanFilePassesThrough(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(src, []byte("nothing sensitive here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := `{"tool_name":"Read","tool_input":{"file_path":` + testenv.JSONString(src) + `}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("Read of clean file should passthrough, got %q", got)
	}
}

func TestPreToolUseReadMissingFileFailsOpen(t *testing.T) {
	in := `{"tool_name":"Read","tool_input":{"file_path":"/nonexistent/path/that/will/never/exist"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("Read of missing file should fail-open (let Cursor surface the error), got %q", got)
	}
}

func TestPreToolUseBadInputFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader("garbage"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

// #48: the redacted temp copy must not land at the old predictable path, and a
// symlink pre-planted there must not be followed.
func TestPreToolUseReadTempPathNotPredictable(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(src, []byte("AWS_KEY="+akia+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(src))
	ctxdir := filepath.Join(tmp, "ctxcop")
	if err := os.MkdirAll(ctxdir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldPredictable := filepath.Join(ctxdir, hex.EncodeToString(sum[:8])+"_"+filepath.Base(src))
	if err := os.Symlink(victim, oldPredictable); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	in := `{"tool_name":"Read","tool_input":{"file_path":` + testenv.JSONString(src) + `}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	updated, _ := m["updated_input"].(map[string]any)
	newPath, _ := updated["file_path"].(string)
	if newPath == "" || newPath == oldPredictable {
		t.Fatalf("temp path missing or still predictable: %q", newPath)
	}
	if data, _ := os.ReadFile(victim); string(data) != "ORIGINAL" {
		t.Errorf("victim overwritten via followed symlink: %q", data)
	}
	data, err := os.ReadFile(newPath)
	if err != nil || strings.Contains(string(data), akia) {
		t.Errorf("temp not written/redacted: err=%v data=%q", err, data)
	}
}

// ---- postToolUse -----------------------------------------------------------

func TestPostToolUseRedactsMCPOutput(t *testing.T) {
	in := `{"tool_name":"MCP:example:lookup","tool_output":{"records":[{"value":"` + akia + `"},{"value":"clean"}]}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	updated, _ := m["updated_mcp_tool_output"].(map[string]any)
	if updated == nil {
		t.Fatalf("missing updated_mcp_tool_output: %q", out.String())
	}
	records, _ := updated["records"].([]any)
	r0, _ := records[0].(map[string]any)
	v0, _ := r0["value"].(string)
	if strings.Contains(v0, akia) {
		t.Errorf("secret leaked: %q", v0)
	}
	if !strings.Contains(v0, "<REDACTED:") {
		t.Errorf("missing placeholder: %q", v0)
	}
	r1, _ := records[1].(map[string]any)
	if got, _ := r1["value"].(string); got != "clean" {
		t.Errorf("non-secret value damaged: %q", got)
	}
}

func TestPostToolUseHandlesJSONStringWrapping(t *testing.T) {
	// Cursor's tool_output sometimes arrives as a JSON-stringified
	// payload. Our handler should unwrap once and scan the inner shape.
	innerJSON := `{"stdout":"AccessKey=` + akia + `"}`
	encoded, _ := json.Marshal(innerJSON)
	in := `{"tool_name":"Shell","tool_output":` + string(encoded) + `}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), akia) {
		t.Errorf("secret leaked through JSON-string wrap: %q", out.String())
	}
}

func TestPostToolUseCleanPasses(t *testing.T) {
	in := `{"tool_name":"Shell","tool_output":{"stdout":"hello world"}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean tool_output should passthrough, got %q", got)
	}
}
