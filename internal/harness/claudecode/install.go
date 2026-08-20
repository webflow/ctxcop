package claudecode

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Scope string

const (
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
)

func SettingsPath(scope Scope) (string, error) {
	switch scope {
	case ScopeUser:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".claude", "settings.json"), nil
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".claude", "settings.json"), nil
	default:
		return "", fmt.Errorf("ctxcop: unknown scope %q", scope)
	}
}

type hookSpec struct {
	event   string
	matcher string // empty omits
	subcmd  string
}

var ownedHooks = []hookSpec{
	{event: "PreToolUse", matcher: ".*", subcmd: "pre-tool-use"},
	{event: "PostToolUse", matcher: ".*", subcmd: "post-tool-use"},
	{event: "UserPromptSubmit", subcmd: "user-prompt-submit"},
	{event: "SessionStart", subcmd: "session-start"},
	{event: "SessionEnd", subcmd: "session-end"},
	{event: "PreCompact", matcher: ".*", subcmd: "pre-compact"},
	{event: "PostCompact", matcher: ".*", subcmd: "post-compact"},
	{event: "Elicitation", matcher: ".*", subcmd: "elicitation"},
	{event: "ElicitationResult", matcher: ".*", subcmd: "elicitation-result"},
}

// Install merges ctxcop hooks into settings.json at the given scope.
// Idempotent — prior ctxcop entries are matched + replaced; unrelated
// hooks and settings are preserved.
func Install(scope Scope, w io.Writer) (string, error) {
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

	var settings map[string]any
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &settings); err != nil {
			return "", fmt.Errorf("ctxcop: existing settings.json is not valid JSON: %w", err)
		}
	}
	if settings == nil {
		settings = map[string]any{}
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		settings["hooks"] = hooks
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
		entry := map[string]any{
			"hooks": []any{
				map[string]any{"type": "command", "command": hookCmd},
			},
		}
		if spec.matcher != "" {
			entry["matcher"] = spec.matcher
		}
		hooks[spec.event] = append(filtered, entry)
	}

	out, err := json.MarshalIndent(settings, "", "  ")
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
	fmt.Fprintf(w, "ctxcop: installed %s hooks → %s\n", strings.Join(events, " + "), path)
	return path, nil
}

// Uninstall removes ctxcop entries, preserves everything else.
// Returns (path, removedCount, error).
func Uninstall(scope Scope, w io.Writer) (string, int, error) {
	path, err := SettingsPath(scope)
	if err != nil {
		return "", 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "ctxcop: no Claude Code settings at %s — nothing to remove.\n", path)
		return path, 0, nil
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return path, 0, fmt.Errorf("ctxcop: existing settings.json is not valid JSON: %w", err)
	}
	hooks, _ := settings["hooks"].(map[string]any)
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
		delete(settings, "hooks")
	}

	if removed == 0 {
		fmt.Fprintf(w, "ctxcop: no ctxcop entries found in %s.\n", path)
		return path, 0, nil
	}

	out, err := json.MarshalIndent(settings, "", "  ")
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
	fmt.Fprintf(w, "ctxcop: removed %d Claude Code hook %s from %s\n", removed, noun, path)
	return path, removed, nil
}

// entryIsOurs matches `<anything> hook <known-subcmd>` rather than the
// literal "ctxcop" — the binary may live at a non-obvious path (brew
// rename, custom install, `go test` binary, etc.).
func entryIsOurs(entry map[string]any) bool {
	list, _ := entry["hooks"].([]any)
	for _, h := range list {
		m, _ := h.(map[string]any)
		cmd, _ := m["command"].(string)
		for _, spec := range ownedHooks {
			if strings.Contains(cmd, " hook "+spec.subcmd) {
				return true
			}
		}
	}
	return false
}
