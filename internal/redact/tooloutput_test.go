package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #56: allow/fixture markers must be honored ONLY on authored-content
// paths, never on untrusted tool output.

// TestRedactToolOutputIgnoresMarkers: a secret in tool output sitting next to
// an allow/fixture marker is STILL redacted. Pre-fix the tool-output paths
// called RedactWithMatches, which honored the marker and leaked the secret.
func TestRedactToolOutputIgnoresMarkers(t *testing.T) {
	for _, marker := range []string{"gitleaks:allow", "ctxcop:allow", "ctxcop:fixture"} {
		in := "leaked = " + awsKey + " # " + marker + "\n"
		out, rules, err := RedactToolOutput(in)
		if err != nil {
			t.Fatalf("RedactToolOutput: %v", err)
		}
		if strings.Contains(out, awsKey) {
			t.Errorf("%s: tool-output secret must be redacted despite marker: %q", marker, out)
		}
		if len(rules) == 0 || !strings.Contains(out, "<REDACTED:") {
			t.Errorf("%s: expected a redaction, got rules=%v out=%q", marker, rules, out)
		}
	}
}

// TestRedactWithMatchesStillHonorsMarkers: the authored/scan path keeps
// honoring markers (regression guard for the split).
func TestRedactWithMatchesStillHonorsMarkers(t *testing.T) {
	in := "fixture = " + awsKey + " # gitleaks:allow\n"
	out, rules, err := RedactWithMatches(in)
	if err != nil {
		t.Fatalf("RedactWithMatches: %v", err)
	}
	if !strings.Contains(out, awsKey) {
		t.Errorf("authored path should honor marker and keep literal: %q", out)
	}
	if len(rules) != 0 {
		t.Errorf("authored path should report no fired rules for suppressed finding, got %v", rules)
	}
}

// TestAuthoredMarkerRequiresProximity: on the authored path a newline-free
// payload where the marker is far from the secret must NOT suppress. Pre-fix,
// betterleaks set f.Line to the whole buffer, so one marker anywhere
// suppressed everything — this test leaked pre-fix.
func TestAuthoredMarkerRequiresProximity(t *testing.T) {
	// Marker >markerProximity bytes away from the secret, on a single line.
	far := awsKey + strings.Repeat("x", markerProximity+50) + " # ctxcop:allow"
	out, err := Redact(far)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(out, awsKey) {
		t.Errorf("distant marker must not suppress newline-free finding: %q", out)
	}

	// Adjacent marker on the same newline-free line still suppresses.
	near := awsKey + " # ctxcop:allow"
	out, err = Redact(near)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.Contains(out, awsKey) {
		t.Errorf("adjacent marker should still suppress: %q", out)
	}
}

// TestMarkerSuppressionAudited: dropping a finding via a marker on the
// authored path writes a traceable marker-suppressed audit entry.
func TestMarkerSuppressionAudited(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("CTXCOP_AUDIT_LOG", logPath)

	if _, err := Redact("fixture = " + awsKey + " # gitleaks:allow\n"); err != nil {
		t.Fatalf("Redact: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), "marker-suppressed") {
		t.Errorf("expected marker-suppressed audit entry, got: %q", string(data))
	}
}
