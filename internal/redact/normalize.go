package redact

import (
	"html"
	"regexp"
	"strings"

	"github.com/betterleaks/betterleaks/report"
)

// Normalization detection passes. These close a class of DETECTION MISSES
// where a credential IS present but an encoding/obfuscation the surface and
// betterleaks-codec scanners don't undo hides it from the rules: zero-width
// runes wedged between a secret's characters, hex written with byte
// delimiters (41-4b-49-…) that betterleaks' contiguous-hex decoder skips, and
// HTML-entity-escaped bytes (&#65;&#75;…).
//
// Each pass is a pure line-local transform applied to a NORMALIZED COPY that
// is fed to the detector. The original bytes are never mutated for detection.
// Redaction stays #45-safe (no false attestation): when a normalized view of
// a line trips a rule, the WHOLE original line is replaced with the
// placeholder — so every encoded form of the secret on that line is gone from
// the output before the rule is attested. Over-redacting the offending line
// is the only acceptable failure direction here, exactly as in Splice's
// verify+over-redact backstop.
//
// Passes are deliberately narrow and detection-gated: a transform only causes
// a redaction when the detector actually fires on the transformed line, so a
// benign UUID/MAC (delimited-hex) or benign HTML (entity-decode) is left alone
// unless it decodes to a real credential shape. Precision is validated against
// the AEB false-positive corpus.

// invisibleRune reports whether r is a zero-width / invisible formatting rune
// that carries no visible content and so must not break a secret's contiguity
// for detection. Bidi controls are included because they can be interleaved to
// the same effect. Code points are written numerically so this source file
// contains no literal invisible characters.
func invisibleRune(r rune) bool {
	switch r {
	case 0x200B, // zero-width space
		0x200C,                                 // zero-width non-joiner
		0x200D,                                 // zero-width joiner
		0x2060,                                 // word joiner
		0xFEFF,                                 // zero-width no-break space / BOM
		0x00AD,                                 // soft hyphen
		0x200E,                                 // left-to-right mark
		0x200F,                                 // right-to-left mark
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // bidi embeddings/overrides
		0x2066, 0x2067, 0x2068, 0x2069: // bidi isolates
		return true
	}
	return false
}

// stripInvisible removes zero-width / invisible formatting runes so a secret
// split by them (AKIA<ZWSP>IOSF…) becomes contiguous for detection.
func stripInvisible(s string) string {
	if !strings.ContainsFunc(s, invisibleRune) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if invisibleRune(r) {
			return -1
		}
		return r
	}, s)
}

// delimitedHexRun matches a run of hex byte-pairs joined by a single ':' , '-'
// or space delimiter (de:ad:be:ef, 41-4b-49-…). Requiring whole 2-hex groups
// separated by exactly one delimiter keeps it from mangling arbitrary
// dash/colon-containing text; the collapsed run is only ever redacted if the
// detector then decodes it to a real credential.
var delimitedHexRun = regexp.MustCompile(`(?i)[0-9a-f]{2}(?:[-: ][0-9a-f]{2}){3,}`)

// collapseDelimitedHex removes the delimiters inside delimited hex-pair runs so
// betterleaks' contiguous-hex codec can decode them. Only runs of 4+ pairs are
// touched (min match in delimitedHexRun) — short groupings aren't worth the
// precision cost.
func collapseDelimitedHex(s string) string {
	return delimitedHexRun.ReplaceAllStringFunc(s, func(run string) string {
		return strings.NewReplacer("-", "", ":", "", " ", "").Replace(run)
	})
}

// entityPattern gates the HTML-entity pass: only decode a line that actually
// carries an entity, so html.UnescapeString isn't run over every line.
var entityPattern = regexp.MustCompile(`&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);`)

// decodeHTMLEntities decodes numeric (&#65; / &#x41;) and named HTML entities
// so an entity-escaped secret (&#65;&#75;&#73;&#65;…) is scanned as its
// decoded bytes.
func decodeHTMLEntities(s string) string {
	if !entityPattern.MatchString(s) {
		return s
	}
	return html.UnescapeString(s)
}

// normalizationPasses are applied per line to produce alternate scan views.
// Order is irrelevant: each produces an independent view.
var normalizationPasses = []func(string) string{
	stripInvisible,
	collapseDelimitedHex,
	decodeHTMLEntities,
}

// normalizedViews returns the distinct normalized forms of line that differ
// from it. A pass that leaves the line unchanged contributes nothing, so lines
// without any obfuscation produce no views and cost no detector calls.
func normalizedViews(line string) []string {
	var views []string
	for _, pass := range normalizationPasses {
		v := pass(line)
		if v == line {
			continue
		}
		dup := false
		for _, existing := range views {
			if existing == v {
				dup = true
				break
			}
		}
		if !dup {
			views = append(views, v)
		}
	}
	return views
}

// redactNormalized runs the normalization detection passes over content and
// returns content with every line whose normalized view trips a rule replaced
// by a placeholder, plus the deduped rule IDs that fired. It is a no-op (bar an
// ANSI-strip + a cheap per-pass check) for content with no obfuscation.
//
// #45 invariant: a rule is only reported after the offending line has been
// fully replaced, so the secret — in the encoded form it took in the original —
// cannot survive in the returned output.
func redactNormalized(content string, honorMarkers bool) (string, []string) {
	if content == "" {
		return content, nil
	}
	d, err := getDetector()
	if err != nil {
		return content, nil
	}
	lines := strings.Split(content, "\n")
	var ruleIDs []string
	seen := make(map[string]struct{})
	changed := false
	for i, line := range lines {
		base := stripANSI(line)
		views := normalizedViews(base)
		if len(views) == 0 {
			continue
		}
		var lineFindings []report.Finding
		for _, v := range views {
			fs := d.DetectString(v)
			fs = dropAnnotatedFindings(fs, honorMarkers)
			lineFindings = append(lineFindings, fs...)
		}
		if len(lineFindings) == 0 {
			continue
		}
		// Over-redact the whole original line: every encoded form of the
		// secret on this line is thereby removed before we attest any rule.
		lines[i] = Placeholder(lineFindings[0])
		changed = true
		for _, f := range lineFindings {
			if _, ok := seen[f.RuleID]; ok {
				continue
			}
			seen[f.RuleID] = struct{}{}
			ruleIDs = append(ruleIDs, f.RuleID)
		}
	}
	if !changed {
		return content, nil
	}
	return strings.Join(lines, "\n"), ruleIDs
}
