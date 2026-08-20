// Package aider integrates ctxcop with Aider (github.com/Aider-AI/aider),
// the terminal AI pair-programming tool.
//
// Aider is structurally different from every other harness ctxcop
// supports. It has no hook system, no callback API, no MCP surface,
// no sub-agents, and no tool-call lifecycle. The PR that would have
// added Claude-Code-style hooks (Aider-AI/aider#4485) was closed with
// the maintainer noting Aider is in maintenance mode; the follow-up
// feature request (#5300) was closed unimplemented. There is nothing
// for ctxcop's usual subprocess-per-event pattern to hook onto.
//
// What Aider does have is a YAML config file (.aider.conf.yml) that
// configures two shell-out points ctxcop can interpose on: lint-cmd
// and test-cmd. Aider feeds their output back into the model's context
// so it can reason about failures — that output path IS the ctxcop
// redaction opportunity. Wrapping those commands through
// `ctxcop run -- bash -c '<original>'` gives us the same value the
// Claude Code Bash wrap provides, at the same layer, just declared
// statically at install time instead of dynamically at PreToolUse.
//
// A pinned context file (Aider's `read:` config key) doubles as the
// SessionStart-equivalent: install writes ~/.aider/ctxcop-priming.md
// and adds a `read:` entry pointing at it, so every Aider session
// starts with the same env-var / <REDACTED:…> guidance the other
// harnesses inject via their SessionStart hooks.
//
// The coverage is narrower than the hook-based adapters. See
// docs/known-limits.md for what's NOT covered (user prompts,
// auto-detected linters, LiteLLM round-trips).
package aider

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"go.yaml.in/yaml/v3"

	"github.com/webflow/ctxcop/internal/shellwrap"
)

// SettingsPath returns Aider's config file location for the scope.
// User scope is ~/.aider.conf.yml (Aider's documented user default).
// Project scope is ./.aider.conf.yml (git-root or cwd, per Aider's
// precedence rules — ctxcop writes to cwd so project-scope installs
// stay next to whatever the user is running from).
func SettingsPath(scope string) (string, error) {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".aider.conf.yml"), nil
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".aider.conf.yml"), nil
	default:
		return "", fmt.Errorf("ctxcop: unknown scope %q", scope)
	}
}

// otherScope returns the scope this package does not currently operate
// on. Aider only has the two scopes install/uninstall support.
func otherScope(scope string) string {
	if scope == "user" {
		return "project"
	}
	return "user"
}

// PrimingPath returns the location of the priming markdown file that
// gets added to Aider's `read:` list. Kept in the user's home so
// project-scope installs still reference a stable, ctxcop-owned path.
func PrimingPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aider", "ctxcop-priming.md"), nil
}

// writeFileNoSymlink writes data to path, refusing if path already
// exists as a symlink. Without this check, a repo-controlled symlink
// at .aider.conf.yml would make os.WriteFile follow it and overwrite
// an arbitrary target outside the workspace.
func writeFileNoSymlink(path string, data []byte, perm os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ctxcop: refusing to write %s: it is a symlink", path)
	}
	return os.WriteFile(path, data, perm)
}

// Install writes/updates the .aider.conf.yml at the given scope and
// writes the priming file. Idempotent: re-running detects existing
// ctxcop wraps and leaves them in place, and never double-wraps.
// Preserves every unrelated YAML key.
func Install(scope string, w io.Writer) (string, error) {
	self := shellwrap.SelfPath()
	path, err := SettingsPath(scope)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}

	primingPath, err := PrimingPath()
	if err != nil {
		return "", err
	}
	if err := writePrimingFile(primingPath); err != nil {
		return "", fmt.Errorf("ctxcop: write priming file: %w", err)
	}

	tree := map[string]any{}
	switch data, rerr := os.ReadFile(path); {
	case rerr == nil:
		if len(data) > 0 {
			if uerr := yaml.Unmarshal(data, &tree); uerr != nil {
				return "", fmt.Errorf("ctxcop: existing %s is not valid YAML: %w", path, uerr)
			}
		}
	case os.IsNotExist(rerr):
		// Fresh install — nothing to merge.
	default:
		return "", fmt.Errorf("ctxcop: reading existing %s: %w", path, rerr)
	}

	_, hadLint := tree["lint-cmd"]
	_, hadTest := tree["test-cmd"]

	wrapped := wrapLintCmd(tree, self)
	if wrapTestCmd(tree, self) {
		wrapped++
	}
	addReadEntry(tree, primingPath)

	if warnings := preflightWarnings(tree); len(warnings) > 0 {
		for _, warning := range warnings {
			fmt.Fprintln(w, "ctxcop: warning — "+warning)
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(tree); err != nil {
		return "", err
	}
	_ = enc.Close()
	if err := writeFileNoSymlink(path, buf.Bytes(), 0o644); err != nil {
		return "", err
	}

	fmt.Fprintf(w, "ctxcop: installed Aider config integration → %s\n", path)
	fmt.Fprintf(w, "ctxcop:   priming file → %s\n", primingPath)
	switch {
	case wrapped > 0:
		fmt.Fprintf(w, "ctxcop:   wrapped %d lint/test command entr%s through `ctxcop run`\n",
			wrapped, map[bool]string{true: "y", false: "ies"}[wrapped == 1])
	case hadLint || hadTest:
		fmt.Fprintln(w, "ctxcop:   lint-cmd / test-cmd already wrapped through `ctxcop run` — nothing to do")
	default:
		fmt.Fprintln(w, "ctxcop:   no lint-cmd / test-cmd found in config — set them to enable output redaction (see docs/harnesses.md#aider)")
	}
	return path, nil
}

// Uninstall removes ctxcop's `read:` entry, un-wraps every lint-cmd /
// test-cmd value ctxcop wrapped, and deletes the priming file if it
// exists and the other scope's config doesn't still reference it.
// Preserves every unrelated key. Returns (path, removed, err), where
// removed counts distinct ctxcop artifacts stripped (matching the
// other harnesses' semantics so the CLI's "n entries removed" totals
// stay consistent).
func Uninstall(scope string, w io.Writer) (string, int, error) {
	self := shellwrap.SelfPath()
	path, err := SettingsPath(scope)
	if err != nil {
		return "", 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(w, "ctxcop: no Aider config at %s — nothing to remove.\n", path)
			return path, 0, nil
		}
		return "", 0, fmt.Errorf("ctxcop: reading existing %s: %w", path, err)
	}
	tree := map[string]any{}
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return path, 0, fmt.Errorf("ctxcop: existing %s is not valid YAML: %w", path, err)
	}

	removed := unwrapLintCmd(tree, self)
	if unwrapTestCmd(tree, self) {
		removed++
	}
	primingPath, _ := PrimingPath()
	if removeReadEntry(tree, primingPath) {
		removed++
	}

	removePrimingFileIfOrphaned := func() {
		if primingStillReferenced(scope, primingPath) {
			return
		}
		_ = os.Remove(primingPath)
	}

	if removed == 0 {
		fmt.Fprintf(w, "ctxcop: no ctxcop entries found in %s.\n", path)
		// Still try to remove the priming file even if the config had
		// no ctxcop references — an orphaned file left behind by a
		// prior partial install is worth cleaning up, as long as the
		// other scope isn't still using it.
		removePrimingFileIfOrphaned()
		return path, 0, nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(tree); err != nil {
		return path, removed, err
	}
	_ = enc.Close()
	if err := writeFileNoSymlink(path, buf.Bytes(), 0o644); err != nil {
		return path, removed, err
	}
	// Priming file is ctxcop-owned; remove it once neither scope's
	// config still references it.
	removePrimingFileIfOrphaned()

	noun := "entries"
	if removed == 1 {
		noun = "entry"
	}
	fmt.Fprintf(w, "ctxcop: removed %d Aider config %s from %s\n", removed, noun, path)
	return path, removed, nil
}

// primingStillReferenced reports whether the scope NOT currently being
// uninstalled still lists primingPath in its `read:` entries. Both
// user- and project-scope installs point at the same shared priming
// file (see PrimingPath), so uninstalling one scope must not delete a
// file the other scope's config still depends on.
func primingStillReferenced(scope, primingPath string) bool {
	otherPath, err := SettingsPath(otherScope(scope))
	if err != nil {
		return false
	}
	data, err := os.ReadFile(otherPath)
	if err != nil {
		return false
	}
	tree := map[string]any{}
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return false
	}
	for _, e := range normalizeStringList(tree["read"]) {
		if e == primingPath {
			return true
		}
	}
	return false
}

// addReadEntry ensures the priming file path is present in the `read`
// list. Aider accepts `read` as either a single string or a list; we
// normalize to a list for deterministic idempotence.
func addReadEntry(tree map[string]any, primingPath string) {
	current := tree["read"]
	entries := normalizeStringList(current)
	for _, e := range entries {
		if e == primingPath {
			return
		}
	}
	entries = append(entries, primingPath)
	sort.Strings(entries)
	tree["read"] = entries
}

// removeReadEntry strips the priming file path from `read`. Returns
// true if a removal happened.
func removeReadEntry(tree map[string]any, primingPath string) bool {
	current, present := tree["read"]
	if !present {
		return false
	}
	entries := normalizeStringList(current)
	kept := make([]string, 0, len(entries))
	found := false
	for _, e := range entries {
		if e == primingPath {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return false
	}
	if len(kept) == 0 {
		delete(tree, "read")
		return true
	}
	tree["read"] = kept
	return true
}

// normalizeStringList unwraps a YAML value that might be a string, a
// []any of strings, or a []string.
func normalizeStringList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// preflightWarnings surfaces install-time advisories the user needs to
// see next to the install report. lint-cmd specifically: if unset,
// Aider falls back to auto-detected per-language linters that bypass
// the wrap entirely (test-cmd has no equivalent auto-detect fallback,
// so it doesn't need the same warning).
func preflightWarnings(tree map[string]any) []string {
	var warnings []string
	if _, hasLint := tree["lint-cmd"]; !hasLint {
		warnings = append(warnings, "no lint-cmd configured. "+
			"Aider will fall back to per-language auto-detected linters, which ctxcop cannot "+
			"intercept. Set lint-cmd explicitly in .aider.conf.yml to activate the ctxcop output "+
			"redaction wrap.")
	}
	return warnings
}

// writePrimingFile writes the SessionStart-equivalent priming text to
// disk. Aider re-reads `read:` entries on every session, so updates
// take effect on the next `aider` invocation without any restart or
// config-reload dance.
func writePrimingFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileNoSymlink(path, []byte(primingMarkdown), 0o644)
}
