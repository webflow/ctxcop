package redact

import (
	"strings"
	"testing"
)

// Investigation: does upstream betterleaks' generic-api-key rule fire on
// shapes that ctxcop would care about catching? If it does, ctxcop's
// "high-entropy fallback" gap (gh issue #2) is already filled and no
// custom rule needed. If it doesn't, we know exactly which shapes slip
// through.
//
// generic-api-key regex (paraphrased): a credential-y keyword
// (key/secret/token/password/credential/access/auth/creds/api) followed
// by an assignment operator (=, :, =>, etc.) followed by a 10-150-char
// alphanumeric-ish value, with a giant stopword filter on the captured
// value to suppress false positives.
//
// We feed it a battery of shapes that mimic what would show up in tool
// output: env-var-style assignments, JSON values, YAML values, header
// strings. Each subtest records the outcome — caught or missed — and
// asserts what we currently observe. If upstream tightens or loosens
// the rule, this test fails and we look at it.
//
// NOTE: these probes are NOT canonical fixtures — they're not real
// credentials, just realistic shapes. They live in this file (test
// suffix) so ctxcop's Write hook leaves them alone.

type genericProbe struct {
	name       string
	input      string
	wantCaught bool
	// wantRule, if non-empty, asserts that specifically this rule ID
	// fired. Empty means "any rule firing counts as caught." We use
	// this to distinguish `generic-api-key` cases from
	// `ctxcop-bearer-token` cases, etc.
	wantRule string
	// Why this probe matters — explains the threat model coverage gap
	// this case represents.
	rationale string
}

func TestGenericAPIKeyProbe(t *testing.T) {
	// All probe values are high-entropy strings that don't match any
	// prefixed family rule (no AKIA, no ghp_, no sk-ant-, etc.) — so
	// generic-api-key is the only rule that could plausibly fire.
	// Values are 32 chars of base32-ish text, intentionally diverse to
	// avoid hitting the upstream stopword list ("000000", "aaaaaa",
	// alphabet runs, common English words, etc.).
	const hi = "Q7VK3M9PZ2HR8XJ5N6WTBFCDEY1AGLOU"

	probes := []genericProbe{
		{
			name:       "env-var-style-assignment",
			input:      "API_KEY=" + hi + "\n",
			wantCaught: true,
			wantRule:   "generic-api-key",
			rationale:  "the canonical shape — `.env` file or `export` output",
		},
		{
			name:       "json-value",
			input:      `{"api_key": "` + hi + `"}`,
			wantCaught: true,
			wantRule:   "generic-api-key",
			rationale:  "config file dump or API response with embedded key",
		},
		{
			name:       "yaml-value",
			input:      "secret: " + hi + "\n",
			wantCaught: true,
			wantRule:   "generic-api-key",
			rationale:  "k8s secret manifest, helm values, github actions",
		},
		{
			name:       "bash-export",
			input:      "export TOKEN=" + hi + "\n",
			wantCaught: true,
			wantRule:   "generic-api-key",
			rationale:  "common in CI logs and shell snippets",
		},
		{
			name:       "authorization-header",
			input:      "Authorization: Bearer " + hi,
			wantCaught: true,
			wantRule:   "ctxcop-bearer-token",
			rationale:  "covered by ctxcop-bearer-token (this probe surfaced the gap; rule added in same change)",
		},
		{
			name:       "naked-high-entropy-string",
			input:      "blob: " + hi,
			wantCaught: false,
			rationale:  "`blob` isn't a credential keyword; this would only fire with an entropy-only rule (which would also catch hashes/UUIDs)",
		},
		{
			name:       "password-equals",
			input:      "password=" + hi,
			wantCaught: true,
			wantRule:   "generic-api-key",
			rationale:  "obvious case, want this to fire",
		},
		{
			name:       "credential-colon",
			input:      "credential: " + hi,
			wantCaught: true,
			wantRule:   "generic-api-key",
			rationale:  "colon-style assignment",
		},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			_, ruleIDs, err := RedactWithMatches(p.input)
			if err != nil {
				t.Fatalf("RedactWithMatches: %v", err)
			}
			caught := len(ruleIDs) > 0
			if caught != p.wantCaught {
				t.Errorf("%s\n  input    = %q\n  caught   = %v\n  expected = %v\n  rules    = %v\n  rationale: %s",
					p.name, p.input, caught, p.wantCaught, ruleIDs, p.rationale)
			}
			// When a specific rule is expected, verify it was the one
			// that fired (not just *some* rule). Distinguishes
			// generic-api-key coverage from ctxcop-bearer-token coverage
			// so we can spot if a probe starts being caught by the
			// wrong rule.
			if p.wantRule != "" {
				hit := false
				for _, id := range ruleIDs {
					if id == p.wantRule {
						hit = true
						break
					}
				}
				if !hit {
					t.Errorf("%s: expected rule %q, got %v", p.name, p.wantRule, ruleIDs)
				}
			}
			if len(ruleIDs) > 0 {
				t.Logf("  fired: %s — %s", strings.Join(ruleIDs, ", "), p.rationale)
			} else {
				t.Logf("  no rule fired — %s", p.rationale)
			}
		})
	}
}
