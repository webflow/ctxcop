// Package shellwrap holds the self-path resolution and POSIX shell
// quoting helpers shared by every harness adapter that wraps a command
// through `ctxcop run -- bash -c '<quoted>'`. Extracted from
// internal/harness/claudecode so the aider adapter (which builds its
// wrap at install time instead of hook time) doesn't duplicate it.
package shellwrap

import (
	"os"
	"strings"
)

// SelfPath returns the absolute path of the running binary, falling
// back to "ctxcop" on resolution failure.
func SelfPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "ctxcop"
}

// Quote returns s as a single POSIX shell word, single-quoting only
// when necessary.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Unquote reverses Quote: given a string that Quote could have
// produced (either a bare unquoted word, or one or more single-quoted
// segments joined by the POSIX `'\”` escape), it returns the original
// value and true. It returns false if s is not fully consumed by a
// single shell word — no trailing content is tolerated, so a wrap
// can't be spoofed by appending unwrapped commands after a
// legitimate-looking quoted argument.
func Unquote(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	if s[0] != '\'' {
		if !strings.ContainsAny(s, " \t\n'\"\\$`") {
			return s, true
		}
		return "", false
	}
	var b strings.Builder
	i := 0
	n := len(s)
	for i < n {
		if s[i] != '\'' {
			return "", false
		}
		i++
		start := i
		for i < n && s[i] != '\'' {
			i++
		}
		if i >= n {
			return "", false // unterminated quote
		}
		b.WriteString(s[start:i])
		i++ // consume closing quote
		if i == n {
			return b.String(), true
		}
		if i+1 < n && s[i] == '\\' && s[i+1] == '\'' {
			b.WriteByte('\'')
			i += 2
			continue
		}
		return "", false // trailing garbage after the quoted word
	}
	return "", false
}
