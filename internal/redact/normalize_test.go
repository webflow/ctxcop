package redact

import (
	"fmt"
	"strings"
	"testing"
)

// The AEB corpus obfuscates the canonical AWS access key (the AKIA…EXAMPLE
// fixture) in three ways that the surface + betterleaks-codec scanners miss.
// Each fixture is BUILT from fragments and encoded at runtime
// so this source file never contains a contiguous credential (nor a
// contiguous hex/entity encoding of one) — same defense as canonical_test.go,
// which also keeps ctxcop's own Write hook from blocking the file.
const aebAWSKey = "AKIA" + "IOSF" + "ODNN" + "7EXA" + "MPLE"

const (
	zwsp = "\u200b" // zero-width space
)

// zeroWidthInsert reproduces enc-zero-width-insert-005: a ZWSP wedged every
// four characters (AKIA<ZWSP>IOSF<ZWSP>…).
func zeroWidthInsert(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteString(zwsp)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// delimitedHex reproduces enc-hex-delimiter-002: each byte as two hex digits,
// joined by dashes (41-4b-49-…).
func delimitedHex(s string) string {
	parts := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		parts = append(parts, fmt.Sprintf("%02x", s[i]))
	}
	return strings.Join(parts, "-")
}

// htmlEntities reproduces body-dlp-html-entity-008: each byte as a decimal
// HTML entity (&#65;&#75;…).
func htmlEntities(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "&#%d;", s[i])
	}
	return b.String()
}

// assertRedactedAsAWS asserts the secret is gone (in every encoded form we
// know how to reproduce) and the AWS rule was attested — the #45 invariant:
// no "redacted" claim for a secret that survived.
func assertRedactedAsAWS(t *testing.T, in string) {
	t.Helper()
	out, rules, err := RedactWithMatches(in)
	if err != nil {
		t.Fatalf("RedactWithMatches: %v", err)
	}
	if !strings.Contains(out, "<REDACTED:") {
		t.Fatalf("no placeholder emitted: %q", out)
	}
	// The decoded key must not survive raw, nor once we re-apply each
	// normalization to the OUTPUT (a surviving encoded form is still a leak).
	if strings.Contains(out, aebAWSKey) ||
		strings.Contains(stripInvisible(out), aebAWSKey) ||
		strings.Contains(decodeHTMLEntities(out), aebAWSKey) ||
		strings.Contains(collapseDelimitedHex(out), delimitedHex(aebAWSKey)) {
		t.Errorf("secret survived in some encoded form: %q", out)
	}
	found := false
	for _, r := range rules {
		if r == "ctxcop-aws-access-key" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ctxcop-aws-access-key attested, got %v", rules)
	}
}

func TestNormalizeZeroWidthInsert(t *testing.T) {
	in := `{"url":"https://evil.example.com/exfil?key=` + zeroWidthInsert(aebAWSKey) + `"}`
	assertRedactedAsAWS(t, in)
}

func TestNormalizeDelimitedHex(t *testing.T) {
	in := `{"url":"https://evil.example.com/exfil?key=` + delimitedHex(aebAWSKey) + `"}`
	assertRedactedAsAWS(t, in)
}

func TestNormalizeHTMLEntities(t *testing.T) {
	in := `<input value="` + htmlEntities(aebAWSKey) + `">`
	assertRedactedAsAWS(t, in)
}

// Tool-output path (markers NOT honored) must redact the obfuscated secret
// too — it's the same normalization code, exercised through RedactToolOutput.
func TestNormalizeToolOutputPath(t *testing.T) {
	in := "leaked key " + zeroWidthInsert(aebAWSKey) + " end"
	out, rules, err := RedactToolOutput(in)
	if err != nil {
		t.Fatalf("RedactToolOutput: %v", err)
	}
	if strings.Contains(stripInvisible(out), aebAWSKey) {
		t.Errorf("secret survived: %q", out)
	}
	if len(rules) == 0 {
		t.Errorf("expected a rule to fire, got none; out=%q", out)
	}
}

// A secret hidden on one line must not blast surrounding clean lines: only the
// offending line is over-redacted.
func TestNormalizePreservesOtherLines(t *testing.T) {
	in := "harmless first line\n" +
		"key=" + delimitedHex(aebAWSKey) + "\n" +
		"harmless third line"
	out, _, err := RedactWithMatches(in)
	if err != nil {
		t.Fatalf("RedactWithMatches: %v", err)
	}
	if !strings.Contains(out, "harmless first line") || !strings.Contains(out, "harmless third line") {
		t.Errorf("clean lines were damaged: %q", out)
	}
	if strings.Contains(collapseDelimitedHex(out), delimitedHex(aebAWSKey)) {
		t.Errorf("secret survived: %q", out)
	}
}

// Precision guard: benign inputs that superficially look like the obfuscations
// (UUID/MAC with delimiters, ordinary HTML entities, zero-width in prose) must
// NOT be redacted. This is the property the AEB false-positive corpus checks;
// pinning it here fails fast if a pass ever gets greedy.
func TestNormalizeDoesNotOverRedact(t *testing.T) {
	benign := []string{
		"request id 550e8400-e29b-41d4-a716-446655440000",
		"device mac de:ad:be:ef:00:01 online",
		"markup &lt;div class=&quot;box&quot;&gt;hello&lt;/div&gt;",
		"price is 5 &amp; up, see &copy; 2026",
		"zero\u200bwidth in the middle of prose text",
		"commit deadbeefcafe1234 pushed to main",
	}
	for _, in := range benign {
		out, rules, err := RedactWithMatches(in)
		if err != nil {
			t.Fatalf("RedactWithMatches(%q): %v", in, err)
		}
		if strings.Contains(out, "<REDACTED:") || len(rules) > 0 {
			t.Errorf("benign input over-redacted: %q -> %q (rules=%v)", in, out, rules)
		}
	}
}

// Unit-level checks on the transforms themselves.
func TestTransforms(t *testing.T) {
	if got := stripInvisible("a" + zwsp + "b"); got != "ab" {
		t.Errorf("stripInvisible: got %q", got)
	}
	if got := collapseDelimitedHex("41-4b-49-41"); got != "414b4941" {
		t.Errorf("collapseDelimitedHex: got %q", got)
	}
	// Fewer than 4 pairs is left alone (below the run threshold).
	if got := collapseDelimitedHex("41-4b"); got != "41-4b" {
		t.Errorf("collapseDelimitedHex short run: got %q", got)
	}
	if got := decodeHTMLEntities("&#65;&#66;"); got != "AB" {
		t.Errorf("decodeHTMLEntities: got %q", got)
	}
	// No entity present -> untouched (and cheap).
	if got := decodeHTMLEntities("plain text"); got != "plain text" {
		t.Errorf("decodeHTMLEntities no-op: got %q", got)
	}
}
