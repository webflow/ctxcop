package redact

import (
	"strings"

	"github.com/betterleaks/betterleaks/report"

	"github.com/webflow/ctxcop/internal/audit"
)

// fixtureMarkers are inline "this is an intentional fixture" annotations,
// honored near the finding on AUTHORED content only. betterleaks' own native
// honoring of the gitleaks/betterleaks signatures is disabled (see
// getDetector), so this list is the single authority: `gitleaks:allow` and
// `betterleaks:allow` are the upstream-compatible forms.
var fixtureMarkers = []string{
	"ctxcop:fixture",
	"ctxcop:allow",
	"gitleaks:allow",
	"betterleaks:allow",
}

// markerProximity bounds how far (in bytes) an allow/fixture marker may sit
// from the matched secret and still suppress the finding. betterleaks sets
// f.Line to the WHOLE payload when the input has no newlines, so an unbounded
// "does f.Line contain a marker" check let one marker anywhere in a newline-
// free buffer suppress every finding (issue #56, the amplification variant).
// We require the marker to share the match's physical line AND sit within this
// many bytes of it.
const markerProximity = 120

// dropAnnotatedFindings removes findings suppressed by an inline allow/fixture
// marker. Marker honoring is ONLY correct for AUTHORED content (Write/Edit
// scanning, `ctxcop scan`): a developer opting a known fixture out of the
// detector. For UNTRUSTED tool output / transcripts honorMarkers must be
// false — otherwise a WebFetch/MCP response or piped command output carrying
// `gitleaks:allow` near a secret would silently bypass redaction (issue #56).
//
// When markers are honored and a finding is dropped, an audit entry records
// the suppression so it stays traceable.
func dropAnnotatedFindings(findings []report.Finding, honorMarkers bool) []report.Finding {
	if len(findings) == 0 || !honorMarkers {
		return findings
	}
	out := findings[:0]
	var suppressed []string
	for _, f := range findings {
		if hasNearbyMarker(f) {
			suppressed = append(suppressed, f.RuleID)
			continue
		}
		out = append(out, f)
	}
	if len(suppressed) > 0 {
		audit.Log(audit.Entry{
			Tool:   "scan",
			Action: "marker-suppressed",
			Rules:  dedupeRules(suppressed),
			Count:  len(suppressed),
		})
	}
	return out
}

// hasNearbyMarker reports whether an allow/fixture marker sits close enough to
// the finding's matched secret to suppress it. The window is the physical line
// (newline-bounded) containing the match, further clamped to markerProximity
// bytes around the match — so a marker on a different line, or far away in a
// newline-free buffer, does NOT suppress.
func hasNearbyMarker(f report.Finding) bool {
	line := f.Line
	if line == "" {
		return false
	}
	match := f.Match
	if match == "" {
		match = f.Secret
	}
	start, end := 0, len(line)
	if match != "" {
		if idx := strings.Index(line, match); idx >= 0 {
			start, end = idx, idx+len(match)
		}
	}
	// Restrict to the physical line (newline-bounded) containing the match.
	lineStart := strings.LastIndexByte(line[:start], '\n') + 1
	lineEnd := len(line)
	if nl := strings.IndexByte(line[start:], '\n'); nl >= 0 {
		lineEnd = start + nl
	}
	// Then clamp to a byte window around the match — the guard against the
	// newline-free case where the physical line is the entire payload.
	lo := start - markerProximity
	if lo < lineStart {
		lo = lineStart
	}
	hi := end + markerProximity
	if hi > lineEnd {
		hi = lineEnd
	}
	if lo > hi {
		return false
	}
	return hasMarker(line[lo:hi])
}

func hasMarker(s string) bool {
	if s == "" {
		return false
	}
	for _, m := range fixtureMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func dedupeRules(rules []string) []string {
	seen := make(map[string]struct{}, len(rules))
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}
