package redact

import (
	"fmt"
	"sync"

	"github.com/betterleaks/betterleaks/detect"

	"github.com/webflow/ctxcop/internal/rules"
)

// ignoreAllowOnce disables betterleaks' native honoring of gitleaks:allow /
// betterleaks:allow comments exactly once, before any DetectString runs. We
// make ctxcop's own dropAnnotatedFindings the single authority on inline
// markers: that's what lets RedactToolOutput ignore markers on untrusted tool
// output (issue #56), and it gives the authored path uniform proximity + audit
// handling for gitleaks:allow too. sync.Once makes the one write to the shared
// singleton detector happen-before every concurrent reader (e.g. the two
// stream pump goroutines).
var ignoreAllowOnce sync.Once

func getDetector() (*detect.Detector, error) {
	d, err := rules.LoadDetector()
	if err != nil {
		return nil, fmt.Errorf("ctxcop: load rules: %w", err)
	}
	ignoreAllowOnce.Do(func() { d.IgnoreGitleaksAllow = true })
	return d, nil
}

// Redact scans AUTHORED content and returns it with each credential-shape
// finding replaced by a placeholder. ANSI escapes are stripped from the scan
// target so colored output like "\x1b[31mAKIA…\x1b[0m" still matches.
// Fail-open on detector init: returns original content + error.
//
// This is an authored-content entry point: inline allow/fixture markers
// (ctxcop:allow, ctxcop:fixture, gitleaks:allow) are honored. For untrusted
// tool output use RedactToolOutput.
func Redact(content string) (string, error) {
	out, _, err := RedactWithMatches(content)
	return out, err
}

// RedactWithMatches is Redact + the rule IDs that fired (for audit). It HONORS
// inline allow/fixture markers and is for AUTHORED content only (Write/Edit/
// NotebookEdit scanning, `ctxcop scan`, prompt/command/tool-input checks).
func RedactWithMatches(content string) (string, []string, error) {
	return redactWithMatches(content, true)
}

// RedactToolOutput redacts UNTRUSTED tool output / transcripts. It behaves
// like RedactWithMatches but does NOT honor inline allow/fixture markers: a
// secret in a Bash output stream, a WebFetch/MCP response, a Read'd file, or a
// compaction transcript is redacted even when it sits next to `gitleaks:allow`
// or `# ctxcop:allow` — whether that marker was planted by an attacker or
// emitted by something like `sed 's/$/ # ctxcop:allow/'` (issue #56). Marker
// honoring is reserved for content the developer authored.
func RedactToolOutput(content string) (string, []string, error) {
	return redactWithMatches(content, false)
}

func redactWithMatches(content string, honorMarkers bool) (string, []string, error) {
	if content == "" {
		return content, nil, nil
	}
	d, err := getDetector()
	if err != nil {
		return content, nil, err
	}
	stripped := stripANSI(content)
	findings := d.DetectString(stripped)
	findings = dropAnnotatedFindings(findings, honorMarkers)
	out := content
	ruleIDs := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	if len(findings) > 0 {
		out = Splice(content, findings)
		// A2 backstop: attest a rule as redacted ONLY after confirming its
		// secret is actually gone from the output. Splice over-redacts as
		// needed, so in practice every finding verifies here — but a
		// "redacted" claim for a secret that survived is exactly the failure
		// this guard exists to prevent (a poisoned audit log and a false hint
		// to the model).
		for _, f := range findings {
			if _, ok := seen[f.RuleID]; ok {
				continue
			}
			forms := secretForms(stripped, f)
			if len(forms) == 0 || leaks(out, forms) {
				continue
			}
			seen[f.RuleID] = struct{}{}
			ruleIDs = append(ruleIDs, f.RuleID)
		}
	}
	// Normalization passes catch credentials the surface + betterleaks-codec
	// scan missed under an obfuscation they don't undo (zero-width runes,
	// delimited hex, HTML entities). Run on the possibly-already-redacted
	// output so a payload carrying both a plain and an obfuscated secret is
	// fully covered. redactNormalized is #45-safe on its own (whole-line
	// over-redaction before attestation).
	out, normRules := redactNormalized(out, honorMarkers)
	for _, r := range normRules {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		ruleIDs = append(ruleIDs, r)
	}
	if out == content {
		// Nothing was redacted (no findings, or nothing that changed the
		// buffer) — return the original untouched, with no attestation.
		return content, nil, nil
	}
	return out, ruleIDs, nil
}
