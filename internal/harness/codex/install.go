package codex

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// SettingsPath returns ~/.codex/config.toml (user) or ./.codex/config.toml
// (project, trusted-only).
func SettingsPath(scope string) (string, error) {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".codex", "config.toml"), nil
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".codex", "config.toml"), nil
	default:
		return "", fmt.Errorf("ctxcop: unknown scope %q", scope)
	}
}

type hookSpec struct {
	event   string
	matcher string // regex on tool_name; "" omits
	subcmd  string
}

// ownedHooks: v0.2.0 Codex coverage. PermissionRequest omitted because
// updatedInput/updatedPermissions fail closed at runtime (#18491).
var ownedHooks = []hookSpec{
	{event: "PreToolUse", matcher: ".*", subcmd: "codex pre-tool-use"},
	{event: "PostToolUse", matcher: ".*", subcmd: "codex post-tool-use"},
	{event: "UserPromptSubmit", subcmd: "codex user-prompt-submit"},
	{event: "SessionStart", subcmd: "codex session-start"},
}

// Fail fast on wedged hooks — a secret scanner that hangs is worse than
// no scanner. Codex's default is 600s; 30s is enough for healthy runs.
const hookTimeoutSeconds = 30

// Install merges ctxcop hooks into Codex config.toml at the given scope,
// preserving every unrelated key + non-ctxcop hook. Idempotent.
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
		if _, derr := toml.Decode(string(data), &tree); derr != nil {
			return "", fmt.Errorf("ctxcop: existing %s is not valid TOML: %w", path, derr)
		}
	}

	emitWarnings(w, tree, filepath.Dir(path))

	hooks, _ := tree["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		tree["hooks"] = hooks
	}

	for _, spec := range ownedHooks {
		hookCmd := fmt.Sprintf("%q hook %s", self, spec.subcmd)
		groups := normalizeGroups(hooks[spec.event])
		filtered := groups[:0]
		for _, g := range groups {
			if !groupIsOurs(g) {
				filtered = append(filtered, g)
			}
		}
		entry := map[string]any{
			"hooks": []map[string]any{
				{"type": "command", "command": hookCmd, "timeout": hookTimeoutSeconds},
			},
		}
		if spec.matcher != "" {
			entry["matcher"] = spec.matcher
		}
		hooks[spec.event] = append(filtered, entry)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(tree); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return "", err
	}

	events := make([]string, 0, len(ownedHooks))
	for _, h := range ownedHooks {
		events = append(events, h.event)
	}
	fmt.Fprintf(w, "ctxcop: installed Codex hooks (%s) → %s\n", joinEvents(events), path)
	return path, nil
}

// normalizeGroups unifies BurntSushi's two decode shapes for
// array-of-tables: []map[string]any or []any containing map[string]any.
func normalizeGroups(v any) []map[string]any {
	switch t := v.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// groupIsOurs matches " hook codex <subcmd>" — same loose-prefix pattern
// as the claudecode adapter.
func groupIsOurs(group map[string]any) bool {
	hooks := normalizeGroups(group["hooks"])
	for _, h := range hooks {
		cmd, _ := h["command"].(string)
		for _, spec := range ownedHooks {
			if containsSubcmd(cmd, spec.subcmd) {
				return true
			}
		}
	}
	return false
}

// Uninstall removes ctxcop entries, preserving every unrelated key.
// Returns (path, removedCount, error).
func Uninstall(scope string, w io.Writer) (string, int, error) {
	path, err := SettingsPath(scope)
	if err != nil {
		return "", 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "ctxcop: no Codex config at %s — nothing to remove.\n", path)
		return path, 0, nil
	}
	tree := map[string]any{}
	if _, derr := toml.Decode(string(data), &tree); derr != nil {
		return path, 0, fmt.Errorf("ctxcop: existing %s is not valid TOML: %w", path, derr)
	}
	hooks, _ := tree["hooks"].(map[string]any)
	if hooks == nil {
		fmt.Fprintf(w, "ctxcop: no [hooks] section in %s — nothing to remove.\n", path)
		return path, 0, nil
	}

	removed := 0
	for _, spec := range ownedHooks {
		groups := normalizeGroups(hooks[spec.event])
		if len(groups) == 0 {
			continue
		}
		kept := make([]map[string]any, 0, len(groups))
		for _, g := range groups {
			if groupIsOurs(g) {
				removed++
				continue
			}
			kept = append(kept, g)
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

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(tree); err != nil {
		return path, removed, err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return path, removed, err
	}
	noun := "entries"
	if removed == 1 {
		noun = "entry"
	}
	fmt.Fprintf(w, "ctxcop: removed %d Codex hook %s from %s\n", removed, noun, path)
	return path, removed, nil
}

func containsSubcmd(cmd, subcmd string) bool {
	// Leading space prevents prefix collisions on argv[0].
	return strings.Contains(cmd, " hook "+subcmd)
}

func joinEvents(events []string) string {
	return strings.Join(events, " + ")
}

// emitWarnings surfaces non-fatal advisories at install time so engineers
// see them with the install report. Two classes: adjacent hooks.json
// (Codex merges + warns at startup), and [features].hooks=false /
// [features].codex_hooks=false (Codex silently drops hook events,
// leaving ctxcop installed-but-inert).
func emitWarnings(w io.Writer, tree map[string]any, dir string) {
	if _, err := os.Stat(filepath.Join(dir, "hooks.json")); err == nil {
		fmt.Fprintln(w, "ctxcop: warning — "+filepath.Join(dir, "hooks.json")+
			" also exists. Codex merges both representations and emits a startup warning. "+
			"Consider consolidating into a single source.")
	}
	features, _ := tree["features"].(map[string]any)
	if features != nil {
		if v, ok := features["hooks"].(bool); ok && !v {
			fmt.Fprintln(w, "ctxcop: warning — [features].hooks = false in config.toml. "+
				"Codex will silently drop hook events; ctxcop will be installed but inert. "+
				"Remove or set true to enable.")
		}
		if v, ok := features["codex_hooks"].(bool); ok && !v {
			fmt.Fprintln(w, "ctxcop: warning — [features].codex_hooks = false (deprecated flag) "+
				"in config.toml. Codex will silently drop hook events; ctxcop will be inert. "+
				"Remove the flag to enable.")
		}
	}
}
