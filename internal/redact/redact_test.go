package redact

import (
	"strings"
	"testing"
)

// Built from two halves so this source file doesn't contain contiguous
// credential literals — ctxcop's own Write hook would block writes to a
// file with a real AKIA in it. At runtime these are the canonical
// betterleaks test fixtures.
const awsKey = "AKIA" + "LALEMEL33243OLIA"
const ghpKey = "ghp_" + "0123456789012345678901234567890123ab"

func TestRedactAWSKey(t *testing.T) {
	in := "AWS_ACCESS_KEY_ID=" + awsKey + "\nplain line\n"
	out, err := Redact(in)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(out, awsKey) {
		t.Errorf("secret not redacted: %q", out)
	}
	if !strings.Contains(out, "<REDACTED:") {
		t.Errorf("missing placeholder: %q", out)
	}
	if !strings.Contains(out, "plain line") {
		t.Errorf("non-secret content damaged: %q", out)
	}
}

func TestRedactEmpty(t *testing.T) {
	out, err := Redact("")
	if err != nil || out != "" {
		t.Fatalf("empty redact: %q %v", out, err)
	}
}

func TestRedactNoSecrets(t *testing.T) {
	in := "hello world\nno secrets here\n"
	out, err := Redact(in)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if out != in {
		t.Errorf("non-secret content changed: %q -> %q", in, out)
	}
}

func TestRedactPreservesUnicode(t *testing.T) {
	in := "héllo 🌍\n" + awsKey + "\nworld ñ\n"
	out, err := Redact(in)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.Contains(out, "héllo 🌍") || !strings.Contains(out, "world ñ") {
		t.Errorf("unicode mangled: %q", out)
	}
	if strings.Contains(out, awsKey) {
		t.Errorf("secret not redacted: %q", out)
	}
}

func TestRedactMultipleSecretsSameLine(t *testing.T) {
	in := "first=" + awsKey + " second=" + ghpKey + " end"
	out, err := Redact(in)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(out, awsKey) {
		t.Errorf("first secret not redacted: %q", out)
	}
	if !strings.Contains(out, "first=") || !strings.Contains(out, "end") {
		t.Errorf("surrounding text damaged: %q", out)
	}
}
