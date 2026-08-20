package aider

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

// Preflight scans the .env files Aider will load and stderr-warns if
// credential-shape values live in them. Meant to be run manually
// before `aider` (the priming file tells the user to add it to a
// shell alias — Aider has no hook to fire it automatically).
//
// Aider's default is to load the .env at the git root; a --env-file
// override is a distinct path. This handler looks in the caller-
// supplied projectRoot (or cwd if empty) and its parent git-root.
//
// Fail-open: any error path (missing file, unreadable, no secrets
// found) exits without a warning.
func Preflight(projectRoot string, w io.Writer) error {
	if pause.IsPaused() {
		return nil
	}
	root := projectRoot
	if root == "" {
		if cwd, err := os.Getwd(); err == nil {
			root = cwd
		}
	}
	if root == "" {
		return nil
	}
	paths := candidateEnvPaths(root)
	hits := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		_, rules, err := redact.RedactWithMatches(string(data))
		if err != nil || len(rules) == 0 {
			continue
		}
		hits += len(rules)
		fmt.Fprintf(w,
			"ctxcop: warning — %s contains %d apparent credential-shape value(s) (%s). "+
				"Aider will load these into its environment, and they may reach the model "+
				"if a wrapped lint/test command echoes them. Move credentials out of .env "+
				"or reference them via an OS-level secrets manager.\n",
			path, len(rules), strings.Join(rules, ", "),
		)
		audit.Log(audit.Entry{
			Tool:   "Aider/preflight",
			Action: "warned",
			Rules:  rules,
			Count:  len(rules),
			Field:  path,
		})
	}
	if hits == 0 {
		// Silent success — same shape as the other harnesses'
		// preflight-style handlers. Nothing to say is the right thing
		// to say.
		return nil
	}
	return nil
}

// candidateEnvPaths mirrors Aider's env-file search order: current
// dir → git root of current dir (if different). We stop there; Aider
// also reads ~/.aider.env but flagging user-scope env files is out
// of scope for a project-level preflight (a user's home-scope .env
// is intentionally global).
func candidateEnvPaths(root string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(p string) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return
		}
		if seen[abs] {
			return
		}
		seen[abs] = true
		out = append(out, abs)
	}
	add(filepath.Join(root, ".env"))
	if gitRoot := findGitRoot(root); gitRoot != "" && gitRoot != root {
		add(filepath.Join(gitRoot, ".env"))
	}
	return out
}

// findGitRoot walks up from start looking for a .git directory. Bounded
// to 32 hops so a symlink loop can't wedge the preflight.
func findGitRoot(start string) string {
	dir := start
	for i := 0; i < 32; i++ {
		if fi, err := os.Stat(filepath.Join(dir, ".git")); err == nil && fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}
