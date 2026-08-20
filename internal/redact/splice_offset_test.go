package redact

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/report"
)

// b64 / hexEnc / pctEnc wrap a plaintext secret in the encodings betterleaks
// recursively decodes. Fixtures are built by concatenation elsewhere; here we
// derive the encoded forms at runtime so this file contains no contiguous
// credential literal.
func b64(s string) string    { return base64.StdEncoding.EncodeToString([]byte(s)) }
func hexEnc(s string) string { return hex.EncodeToString([]byte(s)) }
func pctEnc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// stsToken is the canonical betterleaks AWS session-token test fixture, split
// so this source has no contiguous credential.
const stsToken = "IQoJ" + "B3JpZ2luX2VjEJj//////////wEa" +
	"DGV4YW1wbGVTZXNzaW9uVG9rZW5Gb3JDdHhDb3BUZXN0aW5nMTIzNDU2Nzg5MEFCQ0RFRkdISUprbA=="

// TestRedactionInvariant is the core regression guard for gh issue #45: it
// asserts the security invariant that any time RedactWithMatches attests a
// redaction (non-empty rule set), NONE of the case's secret forms — the raw
// secret OR its encoded wrapper — survive in the output (raw or ANSI-stripped).
// Before the fix, decoded findings were spliced with offsets computed against
// the stripped buffer but applied to a shifted/ANSI-bearing buffer, so the
// encoded secret leaked byte-for-byte while "redacted N" was reported.
func TestRedactionInvariant(t *testing.T) {
	ghpEncB64 := b64("token: " + ghpKey)

	cases := []struct {
		name     string
		in       string
		forms    []string // must be absent from output when a rule fires
		wantFire bool     // detection is expected to fire for this input
	}{
		{
			name:     "surface-aws",
			in:       "AWS_ACCESS_KEY_ID=" + awsKey + "\nplain\n",
			forms:    []string{awsKey},
			wantFire: true,
		},
		{
			name:     "surface-two-per-line",
			in:       "first=" + awsKey + " second=" + ghpKey + " end",
			forms:    []string{awsKey, ghpKey},
			wantFire: true,
		},
		{
			name:     "ansi-wrapped-surface",
			in:       "\x1b[31m" + awsKey + "\x1b[0m plain",
			forms:    []string{awsKey},
			wantFire: true,
		},
		{
			name:     "ansi-interleaved-surface",
			in:       awsKey[:8] + "\x1b[0m" + awsKey[8:],
			forms:    []string{awsKey, awsKey[:8] + "\x1b[0m" + awsKey[8:]},
			wantFire: true,
		},
		{
			name:     "decoded-base64-raw",
			in:       "blob=" + b64(ghpKey),
			forms:    []string{b64(ghpKey), ghpKey},
			wantFire: true,
		},
		{
			name:     "decoded-hex",
			in:       "blob=" + hexEnc(ghpKey),
			forms:    []string{hexEnc(ghpKey), ghpKey},
			wantFire: true,
		},
		{
			name:     "decoded-percent",
			in:       "blob=" + pctEnc(ghpKey),
			forms:    []string{pctEnc(ghpKey), ghpKey},
			wantFire: true,
		},
		{
			// Documented leak (a): STS token collapses to a short placeholder,
			// sliding the decoded window left; the whole base64 PAT survived.
			name:     "leak-a-sts-then-base64-pat",
			in:       stsToken + " blob=" + ghpEncB64,
			forms:    []string{stsToken, ghpEncB64, ghpKey},
			wantFire: true,
		},
		{
			// Documented leak (b): ANSI prefix shifts the offset; a fragment of
			// the encoded PAT (len == preceding ANSI bytes) survived.
			name:     "leak-b-ansi-prefixed-base64",
			in:       "\x1b[31mblob " + ghpEncB64 + "\x1b[0m end",
			forms:    []string{ghpEncB64, ghpKey},
			wantFire: true,
		},
		{
			// Multiple decoded findings sharing a line.
			name:     "two-decoded-one-line",
			in:       "a=" + b64(ghpKey) + " b=" + hexEnc(awsKey),
			forms:    []string{b64(ghpKey), hexEnc(awsKey), ghpKey, awsKey},
			wantFire: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, rules, err := RedactWithMatches(tc.in)
			if err != nil {
				t.Fatalf("RedactWithMatches: %v", err)
			}
			if tc.wantFire && len(rules) == 0 {
				t.Fatalf("expected detection to fire but got no rules; out=%q", out)
			}
			if len(rules) == 0 {
				return // no attestation, invariant vacuous
			}
			outStripped := stripANSI(out)
			for _, form := range tc.forms {
				if form == "" {
					continue
				}
				if strings.Contains(out, form) || strings.Contains(outStripped, form) {
					t.Errorf("INVARIANT VIOLATION: rules=%v attested but secret form "+
						"(len %d) survived in output", rules, len(form))
				}
			}
			if !strings.Contains(out, "<REDACTED:") {
				t.Errorf("rules fired but no placeholder emitted: %q", out)
			}
		})
	}
}

// decodedFinding builds a synthetic decoded finding whose encoded segment is
// stripped[startByte:endByte], mirroring how betterleaks reports 0-indexed
// StartLine and 1-indexed byte columns for the encoded form.
func decodedFinding(stripped string, startByte, endByte int, decodedSecret string) report.Finding {
	// Compute line index and column from the byte offset within stripped.
	line := strings.Count(stripped[:startByte], "\n")
	lineStart := 0
	if line > 0 {
		lineStart = strings.LastIndex(stripped[:startByte], "\n") + 1
	}
	lineEnd := strings.Index(stripped[startByte:], "\n")
	fullLine := stripped[lineStart:]
	if lineEnd >= 0 {
		fullLine = stripped[lineStart : startByte+lineEnd]
	}
	return report.Finding{
		RuleID:      "github-pat",
		StartLine:   line,
		EndLine:     line,
		StartColumn: startByte - lineStart + 1,
		EndColumn:   endByte - lineStart,
		Match:       decodedSecret,
		Secret:      decodedSecret,
		Line:        fullLine,
		Tags:        []string{"decoded:base64"},
	}
}

// TestSpliceByOffsetDirect gives spliceByOffset direct coverage (it had none).
func TestSpliceByOffsetDirect(t *testing.T) {
	enc := b64(ghpKey)

	t.Run("no-ansi-offsets-match-buffer", func(t *testing.T) {
		content := "blob=" + enc
		f := decodedFinding(content, 5, 5+len(enc), "token: "+ghpKey)
		out := spliceByOffset(content, content, f)
		if strings.Contains(out, enc) {
			t.Errorf("encoded segment survived: %q", out)
		}
		if !strings.HasPrefix(out, "blob=<REDACTED:") {
			t.Errorf("expected placeholder spliced in place: %q", out)
		}
	})

	t.Run("offsets-relative-to-stripped-not-content", func(t *testing.T) {
		// Detection ran on `stripped`; `content` carries ANSI around (not
		// inside) the encoded run. Old code applied stripped offsets directly
		// to content and sliced the wrong window — this asserts by-value splice.
		stripped := "AAA blob=" + enc
		content := "\x1b[31mAAA blob=" + enc + "\x1b[0m"
		start := len("AAA blob=")
		f := decodedFinding(stripped, start, start+len(enc), "token: "+ghpKey)
		out := spliceByOffset(content, stripped, f)
		if strings.Contains(out, enc) {
			t.Errorf("encoded segment survived offset/buffer mismatch: %q", out)
		}
		if !strings.Contains(out, "\x1b[31m") || !strings.Contains(out, "\x1b[0m") {
			t.Errorf("ANSI around the segment should be preserved: %q", out)
		}
	})

	t.Run("multi-line-bails-to-line-then-caller", func(t *testing.T) {
		// StartLine != EndLine: encodedSegment refuses; falls back to f.Line.
		content := "prefix\n" + enc + "\nsuffix"
		f := decodedFinding(content, 7, 7+len(enc), "token: "+ghpKey)
		f.EndLine = f.StartLine + 1 // force the multi-line refusal
		out := spliceByOffset(content, content, f)
		// f.Line is the single encoded line, so it can still be removed by value.
		if strings.Contains(out, enc) {
			t.Errorf("encoded line should be removed via f.Line fallback: %q", out)
		}
	})

	t.Run("unresolvable-returns-unchanged", func(t *testing.T) {
		content := "blob=" + enc
		f := decodedFinding(content, 5, 5+len(enc), "token: "+ghpKey)
		f.StartColumn = 9999 // out of range
		f.EndColumn = 10000
		f.Line = "" // and no line to fall back to
		out := spliceByOffset(content, content, f)
		if out != content {
			t.Errorf("unresolvable splice should return content unchanged; got %q", out)
		}
	})
}

// TestSpliceVerificationBackstop asserts the A2 backstop: Splice never returns
// output containing a decoded finding's encoded segment, even when the offset
// splice is a no-op (here forced by corrupting the offsets and the line), by
// falling through to whole-payload over-redaction.
func TestSpliceBackstopOverRedacts(t *testing.T) {
	enc := b64(ghpKey)
	content := "blob=" + enc
	f := decodedFinding(content, 5, 5+len(enc), "token: "+ghpKey)
	// Corrupt offsets so the primary splice can't isolate the segment, but keep
	// f.Line pointing at the real line so secretForms falls back to it.
	f.StartColumn = 0
	f.EndColumn = 0
	out := Splice(content, []report.Finding{f})
	if strings.Contains(out, enc) {
		t.Errorf("backstop failed: encoded secret survived Splice: %q", out)
	}
}
