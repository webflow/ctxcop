package aider

import (
	"regexp"
	"strings"

	"github.com/webflow/ctxcop/internal/shellwrap"
)

// langPrefixRe mirrors Aider's own lint-cmd parser (aider/main.py,
// parse_lint_cmds): `^[a-z]+:.*` — lowercase letters only, and the
// colon does NOT need a following space. Anything wider (uppercase,
// digits, requiring ": ") either mis-parses a value Aider accepts or
// fails to recognize one Aider does.
var langPrefixRe = regexp.MustCompile(`^[a-z]+:`)

// splitLangPrefix parses a "language:command" string using Aider's own
// grammar. Returns (lang, cmd, true) if s begins with a lowercase-only
// language token followed by a colon and a non-empty (post-trim)
// command; ("", "", false) otherwise, so callers fall back to treating
// s as a bare command.
func splitLangPrefix(s string) (lang, cmd string, ok bool) {
	loc := langPrefixRe.FindStringIndex(s)
	if loc == nil {
		return "", "", false
	}
	lang = strings.TrimSuffix(s[loc[0]:loc[1]], ":")
	cmd = strings.TrimSpace(s[loc[1]:])
	if cmd == "" {
		return "", "", false
	}
	return lang, cmd, true
}

// wrapCommand builds the ctxcop wrap for one command. Routing through
// `bash -c` (rather than a bare `ctxcop run -- <cmd>` prefix) means the
// whole original string — compound commands ("a && b"), env-var
// prefixes ("CI=1 pytest"), cd-prefixes — keeps its shell semantics
// intact, and its combined output flows through ctxcop's redactor as a
// single unit instead of only the first shell word.
func wrapCommand(self string, streaming bool, cmd string) string {
	subcmd := "run"
	if streaming {
		subcmd = "run --stream"
	}
	return shellwrap.Quote(self) + " " + subcmd + " -- bash -c " + shellwrap.Quote(cmd)
}

// parseWrap recognizes a string this adapter produced and returns the
// original pre-wrap command. It requires an EXACT structural match —
// the self token immediately followed by the run marker, followed by a
// single quoted shell word that consumes the rest of the string with
// nothing left over — not a substring search anywhere in the value.
// That anchoring is what stops a repo-committed `.aider.conf.yml` from
// planting look-alike marker text (e.g. as a second command joined with
// `&&`/`;`) to trick install into skipping the real wrap.
//
// The self token must equal the resolved binary path (or its quoted
// form) or the bare "ctxcop" PATH-fallback; a token that merely looks
// like a shell word but isn't ctxcop's own identity is rejected, so the
// safe default on any doubt is to wrap again rather than skip.
func parseWrap(s, self string) (inner string, streaming bool, ok bool) {
	trimmed := strings.TrimSpace(s)
	for _, cand := range []string{self, shellwrap.Quote(self), "ctxcop"} {
		if cand == "" {
			continue
		}
		for _, stream := range []bool{true, false} {
			marker := " run -- bash -c "
			if stream {
				marker = " run --stream -- bash -c "
			}
			prefix := cand + marker
			if !strings.HasPrefix(trimmed, prefix) {
				continue
			}
			inner, ok := shellwrap.Unquote(trimmed[len(prefix):])
			if !ok {
				continue
			}
			return inner, stream, true
		}
	}
	return "", false, false
}

// wrapEntry wraps one lint-cmd/test-cmd string, preserving a language
// prefix if present. Returns (newValue, changed); changed is false
// when the entry is already a ctxcop wrap (idempotence).
func wrapEntry(self string, streaming bool, s string) (string, bool) {
	lang, cmd, hasLang := splitLangPrefix(s)
	target := s
	if hasLang {
		target = cmd
	}
	if _, _, already := parseWrap(target, self); already {
		return s, false
	}
	wrapped := wrapCommand(self, streaming, target)
	if hasLang {
		return lang + ": " + wrapped, true
	}
	return wrapped, true
}

// unwrapEntry is the inverse of wrapEntry. Returns (newValue, changed).
func unwrapEntry(self, s string) (string, bool) {
	lang, cmd, hasLang := splitLangPrefix(s)
	target := s
	if hasLang {
		target = cmd
	}
	inner, _, ok := parseWrap(target, self)
	if !ok {
		return s, false
	}
	if hasLang {
		return lang + ": " + inner, true
	}
	return inner, true
}

// wrapStringList applies fn to every string element of a value that may
// be a scalar string, []string, or []any (Aider's `read`/`lint-cmd`
// value shapes), preserving the original container shape. Non-string
// elements are preserved untouched rather than silently dropped.
// Returns the (possibly unchanged) value and the count of elements fn
// reported as changed.
func wrapStringList(current any, fn func(string) (string, bool)) (any, int) {
	switch v := current.(type) {
	case string:
		if v == "" {
			return current, 0
		}
		newVal, changed := fn(v)
		if !changed {
			return current, 0
		}
		return newVal, 1
	case []any:
		out := make([]any, len(v))
		changed := 0
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				out[i] = e
				continue
			}
			newVal, wasChanged := fn(s)
			out[i] = newVal
			if wasChanged {
				changed++
			}
		}
		return out, changed
	case []string:
		out := make([]string, len(v))
		changed := 0
		for i, s := range v {
			newVal, wasChanged := fn(s)
			out[i] = newVal
			if wasChanged {
				changed++
			}
		}
		return out, changed
	default:
		return current, 0
	}
}

// wrapLintCmd rewrites tree["lint-cmd"] so every entry's command side
// runs under the ctxcop wrap. Returns the number of entries newly
// wrapped (0 on a fully-idempotent re-run).
func wrapLintCmd(tree map[string]any, self string) int {
	current, ok := tree["lint-cmd"]
	if !ok {
		return 0
	}
	newVal, changed := wrapStringList(current, func(s string) (string, bool) {
		return wrapEntry(self, false, s)
	})
	tree["lint-cmd"] = newVal
	return changed
}

// unwrapLintCmd strips ctxcop wraps from every lint-cmd entry. Returns
// the number of entries unwrapped.
func unwrapLintCmd(tree map[string]any, self string) int {
	current, ok := tree["lint-cmd"]
	if !ok {
		return 0
	}
	newVal, changed := wrapStringList(current, func(s string) (string, bool) {
		return unwrapEntry(self, s)
	})
	tree["lint-cmd"] = newVal
	return changed
}

// wrapTestCmd rewrites tree["test-cmd"] through the streaming wrap
// (tests often run long; streaming lets partial output surface).
// Returns true if any entry changed.
func wrapTestCmd(tree map[string]any, self string) bool {
	current, ok := tree["test-cmd"]
	if !ok {
		return false
	}
	newVal, changed := wrapStringList(current, func(s string) (string, bool) {
		return wrapEntry(self, true, s)
	})
	tree["test-cmd"] = newVal
	return changed > 0
}

// unwrapTestCmd is the inverse of wrapTestCmd.
func unwrapTestCmd(tree map[string]any, self string) bool {
	current, ok := tree["test-cmd"]
	if !ok {
		return false
	}
	newVal, changed := wrapStringList(current, func(s string) (string, bool) {
		return unwrapEntry(self, s)
	})
	tree["test-cmd"] = newVal
	return changed > 0
}
