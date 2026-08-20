package cursor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

func TestInstallRegistersAllOwnedHooks(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	path, err := Install("user", &out)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join(".cursor", "hooks.json")) {
		t.Errorf("unexpected settings path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatalf("hooks.json not valid JSON: %v\n%s", err, string(data))
	}
	hooks, _ := tree["hooks"].(map[string]any)
	if hooks == nil {
		t.Fatal("hooks key missing")
	}
	for _, spec := range ownedHooks {
		entries, _ := hooks[spec.event].([]any)
		if len(entries) == 0 {
			t.Errorf("event %q has no entries", spec.event)
		}
	}
	report := out.String()
	for _, spec := range ownedHooks {
		if !strings.Contains(report, spec.event) {
			t.Errorf("install report missing event %q: %q", spec.event, report)
		}
	}
}

func TestInstallPreservesUnrelatedHooks(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	preexisting := `{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {"command": "/usr/local/bin/some-other-tool", "matcher": "^Shell$"}
    ],
    "afterShellExecution": [
      {"command": "/usr/local/bin/audit-shell"}
    ]
  }
}`
	if err := os.WriteFile(target, []byte(preexisting), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(target)
	var tree map[string]any
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	hooks := tree["hooks"].(map[string]any)
	// Pre-existing preToolUse other-tool entry should survive next to ctxcop's.
	pre, _ := hooks["preToolUse"].([]any)
	if len(pre) < 2 {
		t.Errorf("expected pre-existing preToolUse entry to survive alongside ctxcop's, got %d: %v", len(pre), pre)
	}
	// afterShellExecution (uncovered by ctxcop) should survive untouched.
	other, _ := hooks["afterShellExecution"].([]any)
	if len(other) != 1 {
		t.Errorf("non-ctxcop afterShellExecution entry lost: %v", other)
	}
}

func TestUninstallRemovesEntriesPreservesUnrelated(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	preexisting := `{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {"command": "/usr/local/bin/some-other-tool", "matcher": "^Shell$"}
    ],
    "afterShellExecution": [
      {"command": "/usr/local/bin/audit-shell"}
    ]
  }
}`
	if err := os.WriteFile(target, []byte(preexisting), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_, removed, err := Uninstall("user", &out)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if removed != len(ownedHooks) {
		t.Errorf("expected %d entries removed, got %d", len(ownedHooks), removed)
	}
	data, _ := os.ReadFile(target)
	var tree map[string]any
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	hooks, _ := tree["hooks"].(map[string]any)
	// Both the non-ctxcop preToolUse entry and the uncovered
	// afterShellExecution entry should survive untouched.
	pre, _ := hooks["preToolUse"].([]any)
	if len(pre) != 1 {
		t.Errorf("expected 1 surviving preToolUse entry, got %d", len(pre))
	}
	other, _ := hooks["afterShellExecution"].([]any)
	if len(other) != 1 {
		t.Errorf("uncovered afterShellExecution lost: %v", other)
	}
	// Events that had only ctxcop entries should be gone entirely.
	for _, ghost := range []string{"postToolUse", "beforeSubmitPrompt", "sessionStart"} {
		if _, present := hooks[ghost]; present {
			t.Errorf("event %q should be removed, still present", ghost)
		}
	}
}

func TestUninstallNoFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	_, removed, err := Uninstall("user", &out)
	if err != nil || removed != 0 {
		t.Errorf("missing file should be no-op success, got removed=%d err=%v", removed, err)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".cursor", "hooks.json"))
	var tree map[string]any
	_ = json.Unmarshal(data, &tree)
	hooks := tree["hooks"].(map[string]any)
	for _, spec := range ownedHooks {
		entries := hooks[spec.event].([]any)
		matched := 0
		for _, e := range entries {
			entry := e.(map[string]any)
			cmd, _ := entry["command"].(string)
			if strings.Contains(cmd, " hook "+spec.subcmd) {
				matched++
			}
		}
		if matched != 1 {
			t.Errorf("event %q has %d entries matching subcmd %q after re-install (want 1)", spec.event, matched, spec.subcmd)
		}
	}
}
