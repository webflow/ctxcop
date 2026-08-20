package codex

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/audit"
)

// Disable audit logging for the entire package's tests. Otherwise audit
// log calls that hit an unset $CTXCOP_AUDIT_LOG are still no-ops, but
// disabling here makes the intent explicit.
func init() { audit.Disable() }

// akia is split so this source file itself doesn't carry a contiguous
// AKIA literal — defense in depth alongside the *_test.* skip pattern.
const akia = "AKIA" + "LALEMEL33243OLIA"

// ---- SessionStart -----------------------------------------------------------

func TestSessionStartEmitsPriming(t *testing.T) {
	var out bytes.Buffer
	if err := SessionStart(&out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if hso == nil {
		t.Fatalf("missing hookSpecificOutput: %q", out.String())
	}
	if got, _ := hso["hookEventName"].(string); got != "SessionStart" {
		t.Errorf("wrong hookEventName: %q", got)
	}
	ctx, _ := hso["additionalContext"].(string)
	// The priming must call out the Codex-specific caveats — those are
	// the bits engineers won't already know from Claude Code conventions.
	for _, want := range []string{
		"ctxcop is active in this Codex session",
		"transparent",                        // we can't transparently wrap commands
		"unified_exec",                       // the silent-bypass tools
		"BLOCKED from reaching your context", // describes PostToolUse behavior
		"parsed but not supported yet",       // explains why we block-not-redact
	} {
		if !strings.Contains(ctx, want) {
			t.Errorf("priming missing %q: %q", want, ctx)
		}
	}
}

// ---- UserPromptSubmit -------------------------------------------------------

func TestUserPromptSubmitBlocksOnSecret(t *testing.T) {
	in := `{"prompt":"please run aws sts get-caller-identity with key ` + akia + `"}`
	var out bytes.Buffer
	if err := UserPromptSubmit(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	// Top-level shape (matches Claude Code's UserPromptSubmit). Codex
	// parses both top-level and nested; the canonical wire path is
	// top-level for this event.
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Errorf("UserPromptSubmit must emit top-level fields, got hookSpecificOutput: %q", out.String())
	}
	if got, _ := m["decision"].(string); got != "block" {
		t.Errorf("decision should be block, got %q", got)
	}
	reason, _ := m["reason"].(string)
	if !strings.Contains(reason, "ctxcop-aws-access-key") {
		t.Errorf("reason missing rule name: %q", reason)
	}
}

func TestUserPromptSubmitCleanPrompt(t *testing.T) {
	in := `{"prompt":"hello world"}`
	var out bytes.Buffer
	if err := UserPromptSubmit(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean prompt should passthrough, got %q", got)
	}
}

// ---- PreToolUse -------------------------------------------------------------

func TestPreToolUseBlocksBashWithSecret(t *testing.T) {
	in := `{"tool_name":"Bash","tool_input":{"command":"export AWS_KEY=` + akia + `; echo done"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if hso == nil {
		t.Fatalf("missing hookSpecificOutput: %q", out.String())
	}
	if got, _ := hso["permissionDecision"].(string); got != "deny" {
		t.Errorf("permissionDecision should be deny, got %q", got)
	}
	reason, _ := hso["permissionDecisionReason"].(string)
	for _, want := range []string{"env var", "ctxcop-aws-access-key", "Codex"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason missing %q: %q", want, reason)
		}
	}
}

func TestPreToolUseAllowsCleanBash(t *testing.T) {
	in := `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean Bash should passthrough, got %q", got)
	}
}

func TestPreToolUseBlocksApplyPatchWithSecret(t *testing.T) {
	// apply_patch uses the same {"command": "..."} shape as Bash in Codex.
	in := `{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: secrets.go\n+const key = \"` + akia + `\"\n*** End Patch"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if got, _ := hso["permissionDecision"].(string); got != "deny" {
		t.Errorf("apply_patch with secret should be denied, got: %q", out.String())
	}
}

func TestPreToolUseBlocksMCPWithSecret(t *testing.T) {
	in := `{"tool_name":"mcp__slack__post","tool_input":{"channel":"#general","text":"share the AWS key ` + akia + ` with the team"}}`
	var out bytes.Buffer
	if err := PreToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if got, _ := hso["permissionDecision"].(string); got != "deny" {
		t.Errorf("MCP with secret should be denied: %q", out.String())
	}
	reason, _ := hso["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "text") {
		t.Errorf("reason should name the offending field: %q", reason)
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

// ---- PostToolUse ------------------------------------------------------------

func TestPostToolUseBlocksBashOutputWithSecret(t *testing.T) {
	// Simulate Codex's Bash response with stdout containing a secret.
	// PostToolUse on Codex must use top-level decision:"block" + reason
	// because updatedMCPToolOutput is parsed-but-not-supported as of
	// May 2026 — emitting it would silently fail open.
	in := `{"tool_name":"Bash","tool_response":{"stdout":"AccessKey=` + akia + `","stderr":"","exit_code":0}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	// Critical: must NOT emit hookSpecificOutput.updatedMCPToolOutput
	// (parsed-but-not-supported). The output should be flat top-level.
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Errorf("Codex PostToolUse must use top-level decision/reason, not hookSpecificOutput.updatedMCPToolOutput (parsed-but-not-supported): %q", out.String())
	}
	if got, _ := m["decision"].(string); got != "block" {
		t.Errorf("decision should be block, got %q (full output: %q)", got, out.String())
	}
	reason, _ := m["reason"].(string)
	// The reason must surface enough for the model to act on: which
	// rule fired, which field, that side effects already happened,
	// and the rotate-the-credential advice.
	for _, want := range []string{
		"ctxcop blocked",
		"ctxcop-aws-access-key",
		"side effects",
		"rotate",
		"updatedMCPToolOutput is parsed-but-not-supported", // explains why we block whole-response
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason missing %q: %q", want, reason)
		}
	}
	// And the reason itself must NOT leak the literal credential.
	if strings.Contains(reason, akia) {
		t.Errorf("reason leaks the literal secret value: %q", reason)
	}
}

func TestPostToolUseCleanResponsePassesThrough(t *testing.T) {
	in := `{"tool_name":"Bash","tool_response":{"stdout":"hello world","exit_code":0}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean response should passthrough, got %q", got)
	}
}

func TestPostToolUseBlocksOnNestedFinding(t *testing.T) {
	// MCP responses can be deeply nested; the walker should find
	// the cred and the reason should name the dotted path so the
	// model knows where it surfaced.
	in := `{"tool_name":"mcp__example__lookup","tool_response":{"data":{"records":[{"id":1,"value":"AccessKey=` + akia + `"}]}}}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	if got, _ := m["decision"].(string); got != "block" {
		t.Errorf("nested cred should block, got %v", m)
	}
	reason, _ := m["reason"].(string)
	if !strings.Contains(reason, "data.records[0].value") {
		t.Errorf("reason should name dotted-path of the finding: %q", reason)
	}
}

func TestPostToolUseHandlesPlainTextResponse(t *testing.T) {
	// Some tools return plain text rather than JSON. The handler
	// should scan it as-is when JSON unmarshal fails.
	// We send a quoted string as the tool_response (valid JSON).
	in := `{"tool_name":"Bash","tool_response":"AccessKey=` + akia + `"}`
	var out bytes.Buffer
	if err := PostToolUse(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	if got, _ := m["decision"].(string); got != "block" {
		t.Errorf("plain-text response with cred should block, got %v", m)
	}
}
