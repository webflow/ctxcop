package redact

import "regexp"

// ansiPattern matches CSI, OSC, and short ESC-prefixed sequences.
// Intentionally liberal — overstripping can't leak; understripping can.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)

// stripANSI removes ANSI escapes. Used as the scan target; replacements
// splice back into the original to preserve coloring around placeholders.
func stripANSI(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}
