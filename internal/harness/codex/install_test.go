package codex

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

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
	if !strings.HasSuffix(path, filepath.Join(".codex", "config.toml")) {
		t.Errorf("unexpected settings path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if _, err := toml.Decode(string(data), &tree); err != nil {
		t.Fatalf("config.toml not valid TOML: %v\n%s", err, string(data))
	}
	hooks, _ := tree["hooks"].(map[string]any)
	if hooks == nil {
		t.Fatal("hooks section missing")
	}
	for _, spec := range ownedHooks {
		entries := normalizeGroups(hooks[spec.event])
		if len(entries) == 0 {
			t.Errorf("event %q has no entries", spec.event)
		}
	}
	report := out.String()
	for _, spec := range ownedHooks {
		if !strings.Contains(report, spec.event) {
			t.Errorf("install report missing %q: %q", spec.event, report)
		}
	}
}

func TestInstallPreservesUnrelatedConfig(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	// Realistic-shape pre-existing config: a model setting and an MCP
	// server block, plus a pre-existing non-ctxcop PreToolUse hook the
	// user added themselves.
	preexisting := `model = "o4-mini"
sandbox_mode = "workspace-write"

[mcp_servers.example]
command = "node"
args = ["/path/to/server.js"]

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/local/bin/some-other-tool"
`
	if err := os.WriteFile(target, []byte(preexisting), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(target)
	var tree map[string]any
	if _, err := toml.Decode(string(data), &tree); err != nil {
		t.Fatalf("post-install TOML invalid: %v\n%s", err, string(data))
	}
	if got, _ := tree["model"].(string); got != "o4-mini" {
		t.Errorf("model setting lost: %v", tree["model"])
	}
	if got, _ := tree["sandbox_mode"].(string); got != "workspace-write" {
		t.Errorf("sandbox_mode setting lost: %v", tree["sandbox_mode"])
	}
	// MCP server block survived.
	mcp, _ := tree["mcp_servers"].(map[string]any)
	example, _ := mcp["example"].(map[string]any)
	if got, _ := example["command"].(string); got != "node" {
		t.Errorf("mcp_servers.example.command lost: %v", example)
	}
	// PreToolUse should now have TWO groups: the pre-existing
	// some-other-tool entry AND ctxcop's.
	hooks, _ := tree["hooks"].(map[string]any)
	pre := normalizeGroups(hooks["PreToolUse"])
	if len(pre) < 2 {
		t.Errorf("expected pre-existing PreToolUse hook to survive alongside ctxcop's, got %d: %v", len(pre), pre)
	}
}

func TestInstallEntriesIncludeTimeout(t *testing.T) {
	// A secret-scanning hook should fail fast. Codex's default is 600s
	// (10m) when timeout is omitted; we want 30s so a wedged ctxcop
	// doesn't silently block real tool calls for minutes.
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".codex", "config.toml"))
	var tree map[string]any
	_, _ = toml.Decode(string(data), &tree)
	hooks := tree["hooks"].(map[string]any)
	for _, spec := range ownedHooks {
		entries := normalizeGroups(hooks[spec.event])
		for _, g := range entries {
			gh := normalizeGroups(g["hooks"])
			for _, h := range gh {
				cmd, _ := h["command"].(string)
				if !strings.Contains(cmd, " hook "+spec.subcmd) {
					continue
				}
				to, ok := h["timeout"].(int64)
				if !ok || to <= 0 {
					t.Errorf("event %q hook entry missing timeout (got %v)", spec.event, h["timeout"])
				}
				if to > 60 {
					t.Errorf("event %q timeout %d too long for a fail-fast secret scanner", spec.event, to)
				}
			}
		}
	}
}

func TestInstallWarnsOnAdjacentHooksJSON(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	codexDir := filepath.Join(dir, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Pre-create hooks.json. Codex would merge with inline [hooks] and
	// emit a startup warning; we surface that at install time.
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	report := out.String()
	if !strings.Contains(report, "hooks.json") {
		t.Errorf("expected warning about hooks.json, got: %q", report)
	}
	if !strings.Contains(report, "warning") {
		t.Errorf("expected the word 'warning' in the install report, got: %q", report)
	}
}

func TestInstallWarnsOnFeaturesHooksFalse(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	// Pre-existing config disables hooks at the feature flag — Codex
	// would silently drop hook events. Install should warn so the
	// engineer knows their install is inert.
	if err := os.WriteFile(target, []byte("[features]\nhooks = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	report := out.String()
	if !strings.Contains(report, "[features].hooks = false") {
		t.Errorf("expected warning naming [features].hooks = false, got: %q", report)
	}
}

func TestInstallWarnsOnDeprecatedCodexHooksFalse(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("[features]\ncodex_hooks = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "codex_hooks = false") {
		t.Errorf("expected warning naming deprecated codex_hooks=false, got: %q", out.String())
	}
}

func TestUninstallRemovesEntriesPreservesUnrelated(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	target := filepath.Join(dir, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	preexisting := `model = "o4-mini"

[mcp_servers.example]
command = "node"
args = ["/path/to/server.js"]

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/local/bin/some-other-tool"
`
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
	if _, err := toml.Decode(string(data), &tree); err != nil {
		t.Fatal(err)
	}
	if got, _ := tree["model"].(string); got != "o4-mini" {
		t.Errorf("model setting lost: %v", tree["model"])
	}
	mcp, _ := tree["mcp_servers"].(map[string]any)
	if _, ok := mcp["example"]; !ok {
		t.Errorf("mcp_servers.example lost: %v", mcp)
	}
	hooks, _ := tree["hooks"].(map[string]any)
	pre := normalizeGroups(hooks["PreToolUse"])
	if len(pre) != 1 {
		t.Errorf("expected 1 surviving PreToolUse entry (the non-ctxcop one), got %d", len(pre))
	}
	// Events that had ONLY ctxcop entries should be deleted entirely.
	for _, ghost := range []string{"PostToolUse", "UserPromptSubmit", "SessionStart"} {
		if _, present := hooks[ghost]; present {
			t.Errorf("event %q should be removed, still present", ghost)
		}
	}
}

func TestUninstallNoConfigIsNoop(t *testing.T) {
	dir := t.TempDir()
	testenv.SetHomeDir(t, dir)
	var out bytes.Buffer
	_, removed, err := Uninstall("user", &out)
	if err != nil || removed != 0 {
		t.Errorf("missing config should be no-op success, got removed=%d err=%v", removed, err)
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
	data, _ := os.ReadFile(filepath.Join(dir, ".codex", "config.toml"))
	var tree map[string]any
	_, _ = toml.Decode(string(data), &tree)
	hooks := tree["hooks"].(map[string]any)
	for _, spec := range ownedHooks {
		entries := normalizeGroups(hooks[spec.event])
		matched := 0
		for _, g := range entries {
			gh := normalizeGroups(g["hooks"])
			for _, h := range gh {
				cmd, _ := h["command"].(string)
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
