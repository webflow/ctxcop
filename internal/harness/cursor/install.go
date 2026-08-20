package cursor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SettingsPath: ~/.cursor/hooks.json (user) or .cursor/hooks.json (project).
func SettingsPath(scope string) (string, error) {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".cursor", "hooks.json"), nil
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".cursor", "hooks.json"), nil
	default:
		return "", fmt.Errorf("ctxcop: unknown scope %q", scope)
	}
}

type hookSpec struct {
	event   string
	matcher string
	subcmd  string
}

// preToolUse matcher gates Shell/Write/Read/MCP only. Read needs preToolUse
// gating because postToolUse's updated_mcp_tool_output is empirically
// MCP-only — built-in Read responses flow unmodified. Grep/Delete/Task
// are lower-risk passthrough today.
var ownedHooks = []hookSpec{
	{event: "preToolUse", matcher: "^(Shell|Write|Read|MCP:.*|mcp__.*)$", subcmd: "cursor pre-tool-use"},
	{event: "postToolUse", matcher: ".*", subcmd: "cursor post-tool-use"},
	{event: "beforeSubmitPrompt", subcmd: "cursor before-submit-prompt"},
	{event: "sessionStart", subcmd: "cursor session-start"},
}

// Install merges ctxcop hooks into Cursor's hooks.json. Idempotent.
func Install(scope string, w io.Writer) (string, error) {
	path, err := SettingsPath(scope)
	if err != nil {
		return "", err
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("ctxcop: resolve self path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}

	tree := map[string]any{}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &tree); err != nil {
			return "", fmt.Errorf("ctxcop: existing %s is not valid JSON: %w", path, err)
		}
	}
	if _, ok := tree["version"]; !ok {
		tree["version"] = 1
	}

	hooks, _ := tree["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		tree["hooks"] = hooks
	}

	for _, spec := range ownedHooks {
		hookCmd := fmt.Sprintf("%q hook %s", self, spec.subcmd)
		existing, _ := hooks[spec.event].([]any)
		filtered := existing[:0]
		for _, e := range existing {
			entry, _ := e.(map[string]any)
			if entry == nil || !entryIsOurs(entry) {
				filtered = append(filtered, e)
			}
		}
		ours := map[string]any{"command": hookCmd}
		if spec.matcher != "" {
			ours["matcher"] = spec.matcher
		}
		hooks[spec.event] = append(filtered, ours)
	}

	out, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return "", err
	}

	events := make([]string, 0, len(ownedHooks))
	for _, h := range ownedHooks {
		events = append(events, h.event)
	}
	fmt.Fprintf(w, "ctxcop: installed Cursor hooks (%s) → %s\n", strings.Join(events, " + "), path)
	return path, nil
}

// Uninstall removes ctxcop entries. Preserves version + non-ctxcop hooks.
// Returns (path, removedCount, error).
func Uninstall(scope string, w io.Writer) (string, int, error) {
	path, err := SettingsPath(scope)
	if err != nil {
		return "", 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "ctxcop: no Cursor hooks.json at %s — nothing to remove.\n", path)
		return path, 0, nil
	}
	tree := map[string]any{}
	if err := json.Unmarshal(data, &tree); err != nil {
		return path, 0, fmt.Errorf("ctxcop: existing %s is not valid JSON: %w", path, err)
	}
	hooks, _ := tree["hooks"].(map[string]any)
	if hooks == nil {
		fmt.Fprintf(w, "ctxcop: no hooks section in %s — nothing to remove.\n", path)
		return path, 0, nil
	}

	removed := 0
	for _, spec := range ownedHooks {
		existing, _ := hooks[spec.event].([]any)
		if len(existing) == 0 {
			continue
		}
		kept := make([]any, 0, len(existing))
		for _, e := range existing {
			entry, _ := e.(map[string]any)
			if entry != nil && entryIsOurs(entry) {
				removed++
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(hooks, spec.event)
		} else {
			hooks[spec.event] = kept
		}
	}
	if len(hooks) == 0 {
		delete(tree, "hooks")
	}

	if removed == 0 {
		fmt.Fprintf(w, "ctxcop: no ctxcop entries found in %s.\n", path)
		return path, 0, nil
	}

	out, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return path, removed, err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return path, removed, err
	}
	noun := "entries"
	if removed == 1 {
		noun = "entry"
	}
	fmt.Fprintf(w, "ctxcop: removed %d Cursor hook %s from %s\n", removed, noun, path)
	return path, removed, nil
}

func entryIsOurs(entry map[string]any) bool {
	cmd, _ := entry["command"].(string)
	for _, spec := range ownedHooks {
		if strings.Contains(cmd, " hook "+spec.subcmd) {
			return true
		}
	}
	return false
}
