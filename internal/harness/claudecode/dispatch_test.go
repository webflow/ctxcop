package claudecode

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

func runHook(t *testing.T, payload string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	return m
}

func hso(m map[string]any) map[string]any {
	v, _ := m["hookSpecificOutput"].(map[string]any)
	return v
}

func TestReadRedactsFileToTemp(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(src, []byte("AWS_KEY="+akia+"\nplain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_name":"Read","tool_input":{"file_path":` + testenv.JSONString(src) + `}}`
	got := runHook(t, payload)
	ui, _ := hso(got)["updatedInput"].(map[string]any)
	if ui == nil {
		t.Fatalf("expected redaction, got %v", got)
	}
	newPath, _ := ui["file_path"].(string)
	if newPath == src {
		t.Errorf("file_path not redirected")
	}
	data, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("read temp: %v", err)
	}
	if strings.Contains(string(data), akia) {
		t.Errorf("temp file still contains secret: %q", data)
	}
	if !strings.Contains(string(data), "<REDACTED:") {
		t.Errorf("temp file missing placeholder: %q", data)
	}
}

func TestReadOfCleanFilePassesThrough(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "ok.txt")
	if err := os.WriteFile(src, []byte("nothing interesting\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"tool_name":"Read","tool_input":{"file_path":` + testenv.JSONString(src) + `}}`
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestWriteBlocksOnSecretInContent(t *testing.T) {
	payload := `{"tool_name":"Write","tool_input":{"file_path":"/x","content":"foo=` + akia + `"}}`
	got := runHook(t, payload)
	h := hso(got)
	if h["permissionDecision"] != "deny" {
		t.Errorf("expected deny, got %v", h)
	}
	reason, _ := h["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "Write") || !strings.Contains(reason, "content") {
		t.Errorf("reason missing tool/field: %q", reason)
	}
	if !strings.Contains(reason, "env var") && !strings.Contains(reason, "process.env") {
		t.Errorf("reason missing workaround hint: %q", reason)
	}
}

func TestEditBlocksOnSecretInNewString(t *testing.T) {
	payload := `{"tool_name":"Edit","tool_input":{"file_path":"/x","old_string":"x","new_string":"key=` + akia + `"}}`
	got := runHook(t, payload)
	h := hso(got)
	if h["permissionDecision"] != "deny" {
		t.Errorf("expected deny, got %v", h)
	}
}

func TestWebFetchBlocksOnSecretInURL(t *testing.T) {
	payload := `{"tool_name":"WebFetch","tool_input":{"url":"https://x.test/?k=` + akia + `","prompt":"go"}}`
	got := runHook(t, payload)
	h := hso(got)
	if h["permissionDecision"] != "deny" {
		t.Errorf("expected deny, got %v", h)
	}
}

func TestMCPBlocksOnNestedSecret(t *testing.T) {
	payload := `{"tool_name":"mcp__slack__send_message","tool_input":{"channel":"#x","blocks":[{"type":"section","text":"debug: ` + akia + `"}]}}`
	got := runHook(t, payload)
	h := hso(got)
	if h["permissionDecision"] != "deny" {
		t.Errorf("expected deny, got %v", h)
	}
	reason, _ := h["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "mcp__slack__send_message") {
		t.Errorf("reason missing tool name: %q", reason)
	}
}

func TestMCPCleanInputPasses(t *testing.T) {
	payload := `{"tool_name":"mcp__slack__send_message","tool_input":{"channel":"#general","text":"hello world"}}`
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough, got %q", got)
	}
}

// --- #49: Bash command secret scanning -------------------------------------

func TestBashBlocksSecretInCurlBearer(t *testing.T) {
	payload := `{"tool_name":"Bash","tool_input":{"command":"curl -H \"Authorization: Bearer ` + akia + `\" https://x.test"}}`
	got := runHook(t, payload)
	h := hso(got)
	if h["permissionDecision"] != "deny" {
		t.Fatalf("expected deny for secret in Bash command, got %v", h)
	}
	reason, _ := h["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "env var") && !strings.Contains(reason, "$TOKEN") {
		t.Errorf("reason missing env-var guidance: %q", reason)
	}
	// Must not smuggle the secret back out via a rewrite.
	if _, ok := h["updatedInput"]; ok {
		t.Errorf("deny must not carry updatedInput: %v", h["updatedInput"])
	}
}

func TestBashBlocksSecretInHeredoc(t *testing.T) {
	cmd := "cat > f <<EOF\nAWS_KEY=" + akia + "\nEOF"
	payload, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": cmd},
	})
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	if hso(m)["permissionDecision"] != "deny" {
		t.Errorf("expected deny for heredoc secret, got %q", out.String())
	}
}

// #47: a clean Bash call is still wrapped, but must NOT assert allow.
func TestBashNoSecretWrapsWithoutAllow(t *testing.T) {
	got := runHook(t, `{"tool_name":"Bash","tool_input":{"command":"echo hi"}}`)
	h := hso(got)
	if _, ok := h["permissionDecision"]; ok {
		t.Errorf("no-secret Bash must not assert permissionDecision, got %v", h["permissionDecision"])
	}
	ui, _ := h["updatedInput"].(map[string]any)
	if ui == nil {
		t.Fatalf("expected wrap via updatedInput, got %v", got)
	}
	if cmd, _ := ui["command"].(string); !strings.Contains(cmd, "bash -c") {
		t.Errorf("command not wrapped: %q", cmd)
	}
}

// --- #49: MultiEdit / write-shaped payload scanning ------------------------

func TestMultiEditBlocksSecretInNestedEdit(t *testing.T) {
	payload := `{"tool_name":"MultiEdit","tool_input":{"file_path":"/x","edits":[` +
		`{"old_string":"a","new_string":"b"},` +
		`{"old_string":"c","new_string":"tok=` + akia + `"}]}}`
	got := runHook(t, payload)
	h := hso(got)
	if h["permissionDecision"] != "deny" {
		t.Fatalf("expected deny for MultiEdit nested secret, got %v", h)
	}
	reason, _ := h["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "edits[1].new_string") {
		t.Errorf("reason should point at the nested field: %q", reason)
	}
}

func TestMultiEditCleanPassesThrough(t *testing.T) {
	payload := `{"tool_name":"MultiEdit","tool_input":{"file_path":"/x","edits":[{"old_string":"a","new_string":"b"}]}}`
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", strings.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough for clean MultiEdit, got %q", got)
	}
}

// --- #48: temp-file safety --------------------------------------------------

func TestReadTempPathNotPredictable(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(src, []byte("AWS_KEY="+akia+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The old predictable target: $TMPDIR/ctxcop/<sha256(src)[:16]>_<basename>.
	sum := sha256.Sum256([]byte(src))
	oldPredictable := filepath.Join(tmp, "ctxcop", hex.EncodeToString(sum[:8])+"_"+filepath.Base(src))

	got := runHook(t, `{"tool_name":"Read","tool_input":{"file_path":`+testenv.JSONString(src)+`}}`)
	ui, _ := hso(got)["updatedInput"].(map[string]any)
	if ui == nil {
		t.Fatalf("expected redaction, got %v", got)
	}
	newPath, _ := ui["file_path"].(string)
	if newPath == oldPredictable {
		t.Fatalf("temp path still uses the old predictable form: %q", newPath)
	}
	if _, err := os.Stat(oldPredictable); err == nil {
		t.Errorf("wrote to the predictable path: %q", oldPredictable)
	}
	data, err := os.ReadFile(newPath)
	if err != nil || strings.Contains(string(data), akia) || !strings.Contains(string(data), "<REDACTED:") {
		t.Errorf("temp not written/redacted: err=%v data=%q", err, data)
	}
}

func TestReadDoesNotFollowPlantedSymlink(t *testing.T) {
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
	// Attacker pre-plants a symlink at the OLD predictable temp path pointing
	// at a victim file. The old os.WriteFile scheme would follow it and clobber
	// the victim; the new scheme writes to an unpredictable dir instead.
	sum := sha256.Sum256([]byte(src))
	ctxdir := filepath.Join(tmp, "ctxcop")
	if err := os.MkdirAll(ctxdir, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(ctxdir, hex.EncodeToString(sum[:8])+"_"+filepath.Base(src))
	if err := os.Symlink(victim, planted); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	runHook(t, `{"tool_name":"Read","tool_input":{"file_path":`+testenv.JSONString(src)+`}}`)

	if data, _ := os.ReadFile(victim); string(data) != "ORIGINAL" {
		t.Errorf("victim overwritten via followed symlink: %q", data)
	}
}
