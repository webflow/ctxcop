package redact

import (
	"strings"
	"testing"
)

// One fixture per credential family ctxcop claims to catch. Adding a new
// rule to embedded/ctxcop.toml without adding a row here will leave the
// new rule un-exercised; deleting a rule without removing its row will
// fail loudly. The goal is to make the rule-set's coverage visible as
// test data, not buried inside a regex pack.
//
// Two non-obvious fixture constraints, both learned the hard way from
// gh issue #2 (an agent ran similar tests with values that "looked
// realistic" but never reached the model as findings):
//
//  1. The fixture must NOT contain the substring
//     "abcdefghijklmnopqrstuvwxyz". Upstream betterleaks ships a global
//     filter `containsAny(finding["secret"], [..., "abcdefghijklmnopqrstuvwxyz"])`
//     to drop obvious dummy values — it eats real-shape findings that
//     happen to include the full alphabet.
//
//  2. The fixture must NOT match `^(?i:a+|b+|...|z+)$` — upstream filter
//     also discards single-letter-repeat strings as obvious dummies.
//
// Each fixture is built via string concatenation (`"prefix_" + "body…"`)
// so this file's literal source doesn't contain a contiguous credential
// shape. Defense-in-depth alongside the *_test.* skip pattern: if this
// file is ever moved out of a test directory, it still won't trip
// ctxcop's own Write hook on save.
//
// For Anthropic and npm, upstream regex requires a terminator
// (quote / whitespace / semicolon / backslash-n/r / end-of-string) AFTER
// the captured secret — we sandwich each fixture with a trailing space
// so the terminator group matches.

const (
	// AWS access key: AKIA + 16 chars [A-Z2-7]. The body is the canonical
	// betterleaks test fixture; gives last-4 fingerprint "OLIA".
	fixtureAWSAccessKey = "AKIA" + "LALEMEL33243OLIA"

	// AWS STS session token: (FwoG|FwoD|IQoJ|IQoD|FQoG) + 100–999 chars
	// of [A-Za-z0-9/+=]. Use 112 chars of mixed base64-ish alphabet.
	fixtureAWSSessionToken = "IQoJ" + "B3JpZ2luX2VjEJj//////////wEa" +
		"DGV4YW1wbGVTZXNzaW9uVG9rZW5Gb3JDdHhDb3BUZXN0aW5nMTIzNDU2Nzg5MEFCQ0RFRkdISUprbA=="

	// GitHub PAT classic: ghp_ + 36 chars [A-Za-z0-9]. Three repeats of
	// the digit alphabet plus six trailing chars. Avoids the
	// abcdefghijklmnopqrstuvwxyz filter.
	fixtureGitHubPATClassic = "ghp_" + "012345678901234567890123456789012345"

	// GitHub fine-grained PAT: github_pat_ + 82 chars [A-Za-z0-9_].
	// Real fine-grained PATs start with "11" (a metadata version byte
	// pair) — keeping that shape so detection is exercised on a
	// realistic payload.
	fixtureGitHubPATFineGrained = "github_pat_" + "11" + "01234567890123456789012345678901234567890123456789012345678901234567890123456789"

	// GitHub app / OAuth / server / refresh token:
	// (gho|ghu|ghs|ghr)_ + 36 chars [A-Za-z0-9]. Use the server token
	// prefix (ghs_) — the rule shares one regex for all four prefixes,
	// so one fixture exercises the whole family.
	fixtureGitHubAppToken = "ghs_" + "012345678901234567890123456789012345"

	// GitLab PAT: glpat- + 20 chars [A-Za-z0-9_-].
	fixtureGitLabPAT = "glpat-" + "01234567890123456789"

	// Slack token: xox[bpoars]- + 10–72 chars [A-Za-z0-9-]. Use the
	// shape Slack actually emits for bot tokens: numeric-dash segments.
	fixtureSlackToken = "xoxb-" + "1234567890-1234567890-ABCDEFGHIJ0123456789"

	// Stripe live secret key: (sk|rk)_(live|test)_ + 24–99 chars
	// [A-Za-z0-9]. 25 chars body keeps comfortably inside the bounds
	// and avoids the alphabet filter.
	fixtureStripeSecretKey = "sk_live_" + "ABCDEFGH0123456789ABCDEFG"

	// Anthropic API key: \b(sk-ant-api03-[a-zA-Z0-9_-]{93}AA) + terminator.
	// 93 chars of body, ending in literal "AA". Trailing space below
	// satisfies the terminator group.
	fixtureAnthropicAPIKey = "sk-ant-api03-" + "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012" + "AA"

	// npm access token: npm_ + 36 chars [a-z0-9] (case-insensitive via
	// (?i) on the upstream rule, but we use lowercase to be safe), with
	// terminator after.
	fixtureNPMToken = "npm_" + "012345678901234567890123456789012345"

	// Bearer token in an HTTP Authorization header. The rule matches
	// `Bearer ` followed by 20+ chars of token-shape. The whole line is
	// the fixture (rule needs the `Bearer ` discriminator); the captured
	// secret is the token portion only.
	fixtureBearerToken = "Authorization: Bearer " + "Q7VK3M9PZ2HR8XJ5N6WTBFCDEY1AGLOU"
)

// canonicalFixture pairs a fixture with the rule ID we expect ctxcop to
// emit in the placeholder. The fixture is sandwiched between markers so
// each subtest asserts that surrounding text survives.
type canonicalFixture struct {
	name       string
	fixture    string
	wantRuleID string
}

func canonicalFixtures() []canonicalFixture {
	return []canonicalFixture{
		{"aws-access-key", fixtureAWSAccessKey, "ctxcop-aws-access-key"},
		{"aws-session-token", fixtureAWSSessionToken, "ctxcop-aws-session-token"},
		{"github-pat-classic", fixtureGitHubPATClassic, "ctxcop-github-pat-classic"},
		{"github-pat-finegrained", fixtureGitHubPATFineGrained, "ctxcop-github-pat-finegrained"},
		{"github-app-token", fixtureGitHubAppToken, "ctxcop-github-app-token"},
		{"gitlab-pat", fixtureGitLabPAT, "ctxcop-gitlab-pat"},
		{"slack-token", fixtureSlackToken, "ctxcop-slack-token"},
		{"stripe-secret-key", fixtureStripeSecretKey, "ctxcop-stripe-secret-key"},
		{"anthropic-api-key", fixtureAnthropicAPIKey, "anthropic-api-key"},
		{"npm-access-token", fixtureNPMToken, "npm-access-token"},
		{"bearer-token", fixtureBearerToken, "ctxcop-bearer-token"},
	}
}

// TestCanonicalCoverage runs one subtest per credential family and
// asserts: the secret is gone from the output, surrounding text is
// intact, and the redaction came from the expected rule. A regression
// where a rule gets accidentally narrowed (or where an upstream filter
// starts eating real findings, as happened with the alphabet-string
// false-positive in gh issue #2) fails LOUDLY here instead of going
// unnoticed.
func TestCanonicalCoverage(t *testing.T) {
	for _, tc := range canonicalFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			const before = "PREFIX_MARKER_BEFORE"
			const after = "POSTFIX_MARKER_AFTER"
			// Trailing space inside the wrapped region satisfies regex
			// terminators (Anthropic, npm) without polluting the
			// surviving-text assertion.
			in := before + " " + tc.fixture + " " + after
			out, ruleIDs, err := RedactWithMatches(in)
			if err != nil {
				t.Fatalf("RedactWithMatches: %v", err)
			}
			if strings.Contains(out, tc.fixture) {
				t.Errorf("secret leaked unredacted: %q", out)
			}
			if !strings.Contains(out, before) || !strings.Contains(out, after) {
				t.Errorf("surrounding markers damaged: %q", out)
			}
			if !strings.Contains(out, "<REDACTED:") {
				t.Errorf("no placeholder emitted: %q", out)
			}
			hit := false
			for _, id := range ruleIDs {
				if id == tc.wantRuleID {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("expected rule %q to fire, got %v; output=%q",
					tc.wantRuleID, ruleIDs, out)
			}
		})
	}
}

// TestCanonicalFixturesAvoidUpstreamFilters guards the fixture set
// itself. If someone adds a fixture that contains the alphabet
// substring or is all-same-letter, upstream betterleaks will discard
// the finding and TestCanonicalCoverage will fail with a confusing
// "no rule fired" message — this test fails first with a clear cause.
func TestCanonicalFixturesAvoidUpstreamFilters(t *testing.T) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	for _, tc := range canonicalFixtures() {
		if strings.Contains(strings.ToLower(tc.fixture), alphabet) {
			t.Errorf("%s: fixture contains %q — upstream filter "+
				"will discard this finding; pick a different body",
				tc.name, alphabet)
		}
		if isSingleLetterRepeat(tc.fixture) {
			t.Errorf("%s: fixture is a single-letter repeat — "+
				"upstream filter will discard it", tc.name)
		}
	}
}

func isSingleLetterRepeat(s string) bool {
	if s == "" {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}
