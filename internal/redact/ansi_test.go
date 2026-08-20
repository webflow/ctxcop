package redact

import (
	"strings"
	"testing"
)

func TestRedactStripsANSIBeforeScanning(t *testing.T) {
	const akia = "AKIA" + "LALEMEL33243OLIA"
	in := "\x1b[31m" + akia + "\x1b[0m plain"
	out, err := Redact(in)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(out, akia) {
		t.Errorf("ANSI-wrapped secret not redacted: %q", out)
	}
	if !strings.Contains(out, "<REDACTED:") {
		t.Errorf("missing placeholder: %q", out)
	}
	if !strings.Contains(out, "\x1b[31m") || !strings.Contains(out, "\x1b[0m") {
		t.Errorf("ANSI codes lost from output: %q", out)
	}
}

func TestStripANSILeavesPlainText(t *testing.T) {
	in := "hello\tworld\n no escapes here"
	if got := stripANSI(in); got != in {
		t.Errorf("plain text changed: %q -> %q", in, got)
	}
}

func TestStripANSICursorCodes(t *testing.T) {
	in := "before\x1b[2J\x1b[Hmid\x1b[6;3Hafter"
	want := "beforemidafter"
	if got := stripANSI(in); got != want {
		t.Errorf("stripANSI: got %q want %q", got, want)
	}
}

// TestRedactANSIInterleavedInsideSecret guards the silent-leak case where
// the detector fires on the ANSI-stripped buffer but Splice's ReplaceAll
// against the original can't find the contiguous secret bytes (because an
// ANSI escape sits between two halves of the credential). The audit log
// and the caller's "redacted N" hint would otherwise claim a redaction
// that never happened — the worst class of failure for a security control.
//
// Acceptance: the literal secret bytes (in any combination of halves
// joined by an ANSI escape) must not survive to the output, and a
// REDACTED placeholder must be present. Losing ANSI fidelity around
// the leak point is the accepted trade-off — color is recoverable, a
// leaked credential is not.
func TestRedactANSIInterleavedInsideSecret(t *testing.T) {
	const akia = "AKIA" + "LALEMEL33243OLIA"
	for _, split := range []int{4, 8, 12, 16} {
		t.Run("split-"+itoa(split), func(t *testing.T) {
			interleaved := akia[:split] + "\x1b[0m" + akia[split:]
			out, rules, err := RedactWithMatches(interleaved)
			if err != nil {
				t.Fatalf("RedactWithMatches: %v", err)
			}
			if len(rules) == 0 {
				t.Fatalf("expected detection to fire on stripped form; got no rules. out=%q", out)
			}
			// Neither half-with-escape nor the contiguous secret may survive.
			if strings.Contains(out, akia) {
				t.Errorf("contiguous secret leaked: %q", out)
			}
			if strings.Contains(out, akia[:split]+"\x1b[0m"+akia[split:]) {
				t.Errorf("interleaved secret survived verbatim: %q", out)
			}
			if !strings.Contains(out, "<REDACTED:") {
				t.Errorf("no placeholder emitted: %q", out)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
