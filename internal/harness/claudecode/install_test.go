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

func TestInstallRegistersAllOwnedHooks(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	path, err := Install(ScopeUser, &out)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join(".claude", "settings.json")) {
		t.Errorf("unexpected settings path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("settings.json not valid JSON: %v", err)
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		t.Fatal("settings.hooks missing")
	}
	// Every ownedHooks entry must produce a registered event. If someone
	// adds a new hook to the ownedHooks slice without exposing the matching
	// `ctxcop hook <subcmd>` dispatch in main.go, brew install will succeed
	// but the hook will fire and exec a non-existent subcommand — the
	// failure surfaces only at runtime. This test is the cheap guard.
	for _, spec := range ownedHooks {
		entries, ok := hooks[spec.event].([]any)
		if !ok || len(entries) == 0 {
			t.Errorf("ownedHook %q missing from settings.hooks", spec.event)
		}
	}
	// Print-out includes all event names — sanity-check the user-facing
	// message stays accurate as we add events.
	report := out.String()
	for _, spec := range ownedHooks {
		if !strings.Contains(report, spec.event) {
			t.Errorf("install report missing event %q: %q", spec.event, report)
		}
	}
}

func TestInstallPreservesUnrelatedSettings(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	preexisting := `{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":"/usr/local/bin/some-other-tool"}]}]}}`
	if err := os.WriteFile(target, []byte(preexisting), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install(ScopeUser, &out); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(target)
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if got, _ := settings["theme"].(string); got != "dark" {
		t.Errorf("unrelated setting lost: %v", settings["theme"])
	}
	pre, _ := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	// Should contain BOTH the pre-existing some-other-tool entry AND
	// ctxcop's entry.
	if len(pre) < 2 {
		t.Errorf("expected pre-existing PreToolUse entry to survive alongside ctxcop's, got %d entries: %v", len(pre), pre)
	}
}

func TestUninstallRemovesCtxcopEntriesPreservesRest(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	preexisting := `{"theme":"dark","hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":"/usr/local/bin/some-other-tool"}]}]}}`
	if err := os.WriteFile(target, []byte(preexisting), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install(ScopeUser, &out); err != nil {
		t.Fatalf("Install: %v", err)
	}
	out.Reset()
	_, removed, err := Uninstall(ScopeUser, &out)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if removed != len(ownedHooks) {
		t.Errorf("expected %d entries removed, got %d", len(ownedHooks), removed)
	}
	data, _ := os.ReadFile(target)
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if got, _ := settings["theme"].(string); got != "dark" {
		t.Errorf("unrelated setting lost: %v", settings["theme"])
	}
	hooks, _ := settings["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Errorf("expected 1 surviving PreToolUse entry (the non-ctxcop one), got %d: %v", len(pre), pre)
	}
	// Events that had ONLY ctxcop entries should be deleted entirely
	// (no vestigial empty arrays that look like leftover state).
	for _, ghost := range []string{"PreCompact", "PostCompact", "Elicitation", "ElicitationResult", "SessionEnd"} {
		if _, present := hooks[ghost]; present {
			t.Errorf("event %q should be removed after uninstall, still present", ghost)
		}
	}
	if !strings.Contains(out.String(), "removed") {
		t.Errorf("report should announce removal: %q", out.String())
	}
}

func TestUninstallNoSettingsFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	_, removed, err := Uninstall(ScopeUser, &out)
	if err != nil {
		t.Fatalf("Uninstall on missing file should be no-op, got: %v", err)
	}
	if removed != 0 {
		t.Errorf("expected 0 removed, got %d", removed)
	}
	if !strings.Contains(out.String(), "nothing to remove") {
		t.Errorf("expected 'nothing to remove' message, got: %q", out.String())
	}
}

func TestUninstallIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	if _, err := Install(ScopeUser, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_, removed1, err := Uninstall(ScopeUser, &out)
	if err != nil || removed1 == 0 {
		t.Fatalf("first uninstall: %v, removed %d", err, removed1)
	}
	out.Reset()
	_, removed2, err := Uninstall(ScopeUser, &out)
	if err != nil {
		t.Fatalf("second uninstall: %v", err)
	}
	if removed2 != 0 {
		t.Errorf("re-uninstall should remove 0 entries, got %d", removed2)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	if _, err := Install(ScopeUser, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := Install(ScopeUser, &out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	var settings map[string]any
	_ = json.Unmarshal(data, &settings)
	hooks := settings["hooks"].(map[string]any)
	// On re-install each event should have exactly ONE entry whose
	// command references our subcmd — no duplication. Counting by
	// subcmd substring is more reliable than entryIsOurs() under test
	// where the test binary path doesn't contain "ctxcop".
	for _, spec := range ownedHooks {
		entries, _ := hooks[spec.event].([]any)
		matched := 0
		for _, e := range entries {
			entry, _ := e.(map[string]any)
			cmds, _ := entry["hooks"].([]any)
			for _, c := range cmds {
				cmdEntry, _ := c.(map[string]any)
				cmd, _ := cmdEntry["command"].(string)
				if strings.Contains(cmd, " hook "+spec.subcmd) {
					matched++
				}
			}
		}
		if matched != 1 {
			t.Errorf("event %q has %d entries matching subcmd %q after re-install (want 1)", spec.event, matched, spec.subcmd)
		}
	}
}
