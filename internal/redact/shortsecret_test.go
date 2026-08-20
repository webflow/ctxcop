package redact

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/report"
)

// Split literals: this file must not contain a contiguous credential.
func cat(parts ...string) string { return strings.Join(parts, "") }

// --- Placeholder fingerprint disclosure (#83) --------------------------------

func TestPlaceholderOmitsFingerprintForShortSecrets(t *testing.T) {
	cases := []struct {
		name      string
		secret    string
		wantTail  bool
		mustNotBe string // substring that must NOT appear in the placeholder
	}{
		// "last 4" of a 4-char secret is the whole secret.
		{name: "4-char secret gets no tail", secret: cat("pa", "ss"), wantTail: false, mustNotBe: cat("pa", "ss")},
		{name: "1-char secret gets no tail", secret: "x", wantTail: false, mustNotBe: "x"},
		{name: "8-char secret gets no tail", secret: cat("hunter", "22"), wantTail: false, mustNotBe: cat("hunter", "22")},
		{name: "11-char secret gets no tail", secret: cat("abcdefg", "hijk"), wantTail: false, mustNotBe: cat("abcdefg", "hijk")},
		// At/above the threshold the fingerprint stays.
		{name: "12-char secret keeps tail", secret: cat("abcdefgh", "wxyz"), wantTail: true},
		{name: "20-char secret keeps tail", secret: cat("AKIA", "LALEMEL33243OLIA"), wantTail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ph := Placeholder(report.Finding{RuleID: "some-rule", Secret: tc.secret})
			if !strings.HasPrefix(ph, "<REDACTED:some-rule") {
				t.Fatalf("unexpected placeholder shape: %q", ph)
			}
			gotTail := strings.Count(ph, ":") > 1
			if gotTail != tc.wantTail {
				t.Errorf("tail present=%v, want %v: %q", gotTail, tc.wantTail, ph)
			}
			if tc.wantTail {
				want := ":" + tc.secret[len(tc.secret)-4:] + ">"
				if !strings.HasSuffix(ph, want) {
					t.Errorf("expected last-4 fingerprint %q in %q", want, ph)
				}
			}
			if tc.mustNotBe != "" && strings.Contains(ph, tc.mustNotBe) {
				t.Errorf("placeholder discloses the secret: %q", ph)
			}
		})
	}
}

// --- The #83 data-destruction bug -------------------------------------------

// A short password collides with prose; that used to nuke the whole payload.
func TestShortSecretDoesNotDestroyUnrelatedLines(t *testing.T) {
	dsn := cat("postgres://", "u", ":", "pa", "ss", "@db")
	unrelated := "unrelated line mentioning " + cat("pa", "ssword") + " and " + cat("pa", "ssthrough")
	content := dsn + "\n" + unrelated + "\n"

	out, rules, err := RedactToolOutput(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatalf("expected the DSN to be detected; got no rules")
	}
	if !strings.Contains(out, "unrelated line mentioning") {
		t.Errorf("unrelated line was destroyed by over-redaction:\n%q", out)
	}
	if strings.Contains(out, dsn) {
		t.Errorf("the DSN survived redaction:\n%q", out)
	}
	if !strings.Contains(out, "REDACTED:") {
		t.Errorf("expected a placeholder in the output:\n%q", out)
	}
	// #45 invariant: the credential-bearing authority must be gone.
	if strings.Contains(out, cat(":", "pa", "ss", "@")) {
		t.Errorf("password authority survived:\n%q", out)
	}
}

// --- Properties the fix must NOT weaken -------------------------------------

// The splice removes only the labeled match, so the backstop must catch the
// bare copy. This is what the substring check exists for.
func TestLongResidualSecretStillOverRedacts(t *testing.T) {
	secret := cat("wJalrXUtnFEMI", "/K7MDENG/", "bPxRfiCYEXAMPLEKEY") // 40 chars
	content := cat("aws_secret_access_key=", secret) + "\n" +
		cat("archived_copy=", secret) + "\n"

	out, rules, err := RedactToolOutput(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatalf("expected detection; got no rules")
	}
	if strings.Contains(out, secret) {
		t.Errorf("bare residual copy of the secret survived — this is a leak:\n%q", out)
	}
}

// A standalone residual IS still a leak; only mid-word substrings are exempt.
func TestShortSecretAtTokenBoundaryStillOverRedacts(t *testing.T) {
	short := cat("pa", "ss")
	content := cat("postgres://", "u", ":", short, "@db") + "\n" +
		"the value is " + short + " here\n"

	out, _, err := RedactToolOutput(content)
	if err != nil {
		t.Fatal(err)
	}
	// The standalone occurrence must not survive verbatim in its original line.
	if strings.Contains(out, "the value is "+short+" here") {
		t.Errorf("standalone short secret survived; expected over-redaction:\n%q", out)
	}
}

// --- leaks() unit behavior ---------------------------------------------------

// Covered by the token-boundary rule (rule IDs are hyphen-delimited), NOT by
// exempting placeholder-shaped regions — see the forged-placeholder test.
func TestLeaksIgnoresRuleIDCollisionViaTokenBoundary(t *testing.T) {
	ph := Placeholder(report.Finding{RuleID: "ctxcop-aws-access-key", Secret: "aws"})
	if leaks(ph, []string{"aws"}) {
		t.Errorf("form occurring only inside a hyphenated rule ID must not count as a leak: %q", ph)
	}
}

// Untrusted output must not suppress its own redaction via a placeholder-shaped
// string. Masking those from the leak check made this smuggle the secret. (#88)
func TestForgedPlaceholderCannotSmuggleSecret(t *testing.T) {
	secret := cat("wJalrXUtnFEMI", "/K7MDENG/", "bPxRfiCYEXAMPLEKEY") // 40 chars
	// Line 1's labeled match is spliced; line 2's forged wrapper is not.
	content := cat("aws_secret_access_key=", secret) + "\n" +
		"<REDACTED:forged:" + secret + ">\n"

	out, rules, err := RedactToolOutput(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatalf("expected detection; got no rules")
	}
	if strings.Contains(out, secret) {
		t.Errorf("forged placeholder smuggled the secret past verification — ctxcop reported %v as redacted while the literal survived:\n%q", rules, out)
	}
}

func TestLeaksTokenBoundaryRules(t *testing.T) {
	short := cat("pa", "ss")
	cases := []struct {
		name  string
		text  string
		form  string
		leaks bool
	}{
		{"short form mid-word is not a leak", cat("pa", "ssword") + " and " + cat("pa", "ssthrough"), short, false},
		{"short form as standalone token is a leak", "value is " + short + " here", short, true},
		{"short form at end of input is a leak", "value=" + short, short, true},
		{"short form after punctuation is a leak", "(" + short + ")", short, true},
		{"short form abutted by digits is not a leak", short + "1234", short, false},
		{"short form abutted by underscore is not a leak", "x_" + short + "_y", short, false},
		// Long forms keep the substring check regardless of abutment.
		{"long form abutted is still a leak", "junk" + strings.Repeat("A", 40) + "junk", strings.Repeat("A", 40), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := leaks(tc.text, []string{tc.form}); got != tc.leaks {
				t.Errorf("leaks(%q, %q) = %v, want %v", tc.text, tc.form, got, tc.leaks)
			}
		})
	}
}
