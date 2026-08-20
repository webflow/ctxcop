package redact

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/report"
)

// Below this length a `:last4` tail discloses too much of the secret — at n<=4
// it IS the secret. (#83)
const minFingerprintLen = 12

// Placeholder builds "<REDACTED:<rule-id>:<last-4-of-secret>>", omitting the
// fingerprint below minFingerprintLen.
func Placeholder(f report.Finding) string {
	rule := strings.ReplaceAll(strings.ToLower(f.RuleID), " ", "-")
	if rule == "" {
		rule = "secret"
	}
	secret := f.Secret
	if secret == "" {
		secret = f.Match
	}
	tail := ""
	if n := len(secret); n >= minFingerprintLen {
		tail = ":" + secret[n-4:]
	}
	return fmt.Sprintf("<REDACTED:%s%s>", rule, tail)
}

// Splice replaces every finding's matched substring with a placeholder and
// guarantees, per finding, that the secret cannot survive in the output.
//
// Detection runs on the ANSI-stripped buffer, so decoded findings' byte
// offsets are relative to stripANSI(content). We reproduce that buffer here
// (stripANSI is deterministic) and resolve offsets against it — never against
// the original content, whose length and byte positions differ once ANSI is
// present or an earlier surface replacement has run.
//
// Surface findings (rule matched raw content) use strings.ReplaceAll on
// f.Match — UTF-8 safe and position-independent.
//
// Decoded findings (`decoded:*` tag — rule matched base64/hex/percent/unicode
// content) have f.Match as the DECODED secret, which doesn't appear in the raw
// text. The encoded segment is spliced out via StartColumn/EndColumn offsets
// into the stripped buffer (see spliceByOffset).
//
// After each finding's splice we VERIFY the secret is actually gone. If it
// survived — interleaved ANSI, a no-op replace, or a segment that couldn't be
// isolated — we fall back to over-redaction: replace the whole line, then the
// whole payload. Over-redaction is the only acceptable failure direction; a
// false "redacted" attestation is the one a secret scanner must never emit.
func Splice(content string, findings []report.Finding) string {
	if len(findings) == 0 || content == "" {
		return content
	}
	stripped := stripANSI(content)
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		forms := secretForms(stripped, f)
		if len(forms) == 0 {
			continue
		}
		key := f.RuleID + "\x00" + strings.Join(forms, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		content = redactFinding(content, stripped, f, forms)
	}
	return content
}

// redactFinding splices out a single finding and then over-redacts if the
// secret survived the splice.
func redactFinding(content, stripped string, f report.Finding, forms []string) string {
	ph := Placeholder(f)
	if isDecodedFinding(f) {
		content = spliceByOffset(content, stripped, f)
	} else {
		match := f.Match
		if match == "" {
			match = f.Secret
		}
		content = strings.ReplaceAll(content, match, ph)
	}
	if !leaks(content, forms) {
		return content
	}
	// Backstop 1: over-redact each line that still carries the secret.
	content = redactLeakingLines(content, forms, ph)
	if !leaks(content, forms) {
		return content
	}
	// Backstop 2: the secret couldn't be isolated to a line (it spans lines,
	// or offsets/line search all missed). Drop the whole payload.
	return ph
}

func isDecodedFinding(f report.Finding) bool {
	for _, t := range f.Tags {
		if strings.HasPrefix(t, "decoded:") {
			return true
		}
	}
	return false
}

// secretForms returns the raw byte sequences that must NOT appear in redacted
// output for finding f. For decoded findings the encoded segment (resolved
// from the stripped buffer) is the form that shows up in the raw stream;
// f.Secret/f.Match hold the DECODED value, which never appears raw. For
// surface findings the match and secret are those forms directly.
func secretForms(stripped string, f report.Finding) []string {
	var forms []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, e := range forms {
			if e == s {
				return
			}
		}
		forms = append(forms, s)
	}
	if isDecodedFinding(f) {
		if enc, ok := encodedSegment(stripped, f); ok {
			add(enc)
		}
		if len(forms) == 0 {
			// Offsets couldn't isolate the encoded segment; fall back to the
			// detector's line as the thing that must not survive verbatim.
			add(f.Line)
		}
		return forms
	}
	add(f.Match)
	add(f.Secret)
	return forms
}

// spliceByOffset removes a decoded finding's encoded segment from content.
//
// The offsets index the ANSI-stripped buffer the detector scanned, so the
// encoded bytes are resolved there and then spliced out of content BY VALUE
// (position-independent). Splicing by value — rather than by raw offset into
// content — is what makes this correct when an earlier surface replacement has
// shifted content or when ANSI surrounds the segment. Returns content
// unchanged when the segment can't be isolated; redactFinding over-redacts
// afterward via the verify backstop.
func spliceByOffset(content, stripped string, f report.Finding) string {
	ph := Placeholder(f)
	if enc, ok := encodedSegment(stripped, f); ok {
		if strings.Contains(content, enc) {
			return strings.ReplaceAll(content, enc, ph)
		}
	}
	if f.Line != "" && strings.Contains(content, f.Line) {
		return strings.ReplaceAll(content, f.Line, ph)
	}
	return content
}

// encodedSegment returns the raw encoded bytes for a decoded finding, taken
// from the ANSI-stripped buffer the detector scanned. betterleaks reports a
// 0-indexed StartLine and 1-indexed byte columns for the encoded segment.
func encodedSegment(stripped string, f report.Finding) (string, bool) {
	if f.StartLine != f.EndLine {
		return "", false
	}
	lineStarts := lineStartOffsets(stripped)
	if f.StartLine < 0 || f.StartLine >= len(lineStarts) {
		return "", false
	}
	start := lineStarts[f.StartLine] + f.StartColumn - 1
	end := lineStarts[f.StartLine] + f.EndColumn
	if start < 0 || end > len(stripped) || start >= end {
		return "", false
	}
	return stripped[start:end], true
}

func lineStartOffsets(s string) []int {
	starts := []int{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// Forms this short collide with prose ("pass" inside "password"), so a residual
// needs a token boundary to count. Longer forms keep the plain substring check —
// under-detection is the wrong failure direction. (#83)
const shortFormMaxLen = 12

// isTokenByte reports whether the byte at i continues an identifier-ish run.
// Out-of-range counts as a boundary.
func isTokenByte(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c == '_' || c == '-' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// occursAsToken reports whether form appears in text with a non-token byte on
// both sides — i.e. as a value in its own right rather than as a fragment of a
// longer word.
func occursAsToken(text, form string) bool {
	for i := 0; i+len(form) <= len(text); {
		j := strings.Index(text[i:], form)
		if j < 0 {
			return false
		}
		start := i + j
		if !isTokenByte(text, start-1) && !isTokenByte(text, start+len(form)) {
			return true
		}
		i = start + 1
	}
	return false
}

// formSurvives reports whether one form still constitutes a leak in text.
func formSurvives(text, form string) bool {
	if len(form) <= shortFormMaxLen {
		return occursAsToken(text, form)
	}
	return strings.Contains(text, form)
}

// leaks reports whether any form still appears in text, raw or ANSI-stripped —
// an escape interleaved through a secret still leaks it.
//
// INVARIANT: never exempt a region of `text` from this check based on its
// content. Masking `<REDACTED:…>`-shaped substrings here let untrusted output
// smuggle a live secret through a forged placeholder. (#56, #88)
func leaks(text string, forms []string) bool {
	stripped := ""
	strippedComputed := false
	for _, form := range forms {
		if formSurvives(text, form) {
			return true
		}
		if !strippedComputed {
			stripped = stripANSI(text)
			strippedComputed = true
		}
		if stripped != text && formSurvives(stripped, form) {
			return true
		}
	}
	return false
}

// redactLeakingLines replaces every line that still carries a leaked form with
// a placeholder. Lines that don't leak (including their ANSI) are untouched.
func redactLeakingLines(content string, forms []string, ph string) string {
	if !strings.Contains(content, "\n") {
		if leaks(content, forms) {
			return ph
		}
		return content
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if leaks(line, forms) {
			lines[i] = ph
		}
	}
	return strings.Join(lines, "\n")
}
