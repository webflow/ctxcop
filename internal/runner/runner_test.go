package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Built from two halves so this source file doesn't contain a contiguous
// AWS-key literal — ctxcop's own Write hook would block writes to it.
const awsKey = "AKIA" + "LALEMEL33243OLIA"

func TestRunRedactsStdout(t *testing.T) {
	var out, errb bytes.Buffer
	code, err := Run(context.Background(), []string{"sh", "-c", "echo prefix " + awsKey + " suffix"}, &out, &errb)
	if err != nil || code != 0 {
		t.Fatalf("Run: code=%d err=%v", code, err)
	}
	if strings.Contains(out.String(), awsKey) {
		t.Errorf("secret leaked to stdout: %q", out.String())
	}
	if !strings.Contains(out.String(), "<REDACTED:") {
		t.Errorf("missing placeholder: %q", out.String())
	}
	if !strings.Contains(out.String(), "prefix") || !strings.Contains(out.String(), "suffix") {
		t.Errorf("surrounding text damaged: %q", out.String())
	}
}

func TestRunRedactsStderr(t *testing.T) {
	var out, errb bytes.Buffer
	code, err := Run(context.Background(), []string{"sh", "-c", "echo " + awsKey + " >&2"}, &out, &errb)
	if err != nil || code != 0 {
		t.Fatalf("Run: code=%d err=%v", code, err)
	}
	if strings.Contains(errb.String(), awsKey) {
		t.Errorf("secret leaked to stderr: %q", errb.String())
	}
}

func TestRunPropagatesNonZeroExit(t *testing.T) {
	var out, errb bytes.Buffer
	code, err := Run(context.Background(), []string{"sh", "-c", "exit 42"}, &out, &errb)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 42 {
		t.Errorf("expected exit 42, got %d", code)
	}
}

func TestRunMissingBinary(t *testing.T) {
	var out, errb bytes.Buffer
	code, _ := Run(context.Background(), []string{"/no/such/binary/ctxcop-test"}, &out, &errb)
	if code == 0 {
		t.Errorf("expected non-zero exit, got 0")
	}
}

// Issue #56: command output is untrusted tool output, so an inline
// allow/fixture marker in the stream must NOT suppress redaction (e.g.
// `cat .env | sed 's/$/ # ctxcop:allow/'`). Pre-fix, emit honored the marker
// and the secret leaked to stdout.
func TestRunIgnoresMarkersInOutput(t *testing.T) {
	var out, errb bytes.Buffer
	code, err := Run(context.Background(),
		[]string{"sh", "-c", "echo " + awsKey + " '# ctxcop:allow'"}, &out, &errb)
	if err != nil || code != 0 {
		t.Fatalf("Run: code=%d err=%v", code, err)
	}
	if strings.Contains(out.String(), awsKey) {
		t.Errorf("marker in untrusted output must not suppress redaction: %q", out.String())
	}
	if !strings.Contains(out.String(), "<REDACTED:") {
		t.Errorf("missing placeholder: %q", out.String())
	}
}

// Issue #58: a streamed redaction must emit the guidance hint and write an
// audit entry, matching the buffered Run path. Pre-fix, pump discarded emit's
// rule IDs so a backgrounded command's redaction was a silent drop.
func TestRunStreamingLogsAndHints(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("CTXCOP_AUDIT_LOG", logPath)

	var out, errb bytes.Buffer
	code, err := RunStreaming(context.Background(),
		[]string{"sh", "-c", "echo " + awsKey}, &out, &errb)
	if err != nil || code != 0 {
		t.Fatalf("RunStreaming: code=%d err=%v", code, err)
	}
	if strings.Contains(out.String(), awsKey) {
		t.Errorf("secret leaked: %q", out.String())
	}
	if !strings.Contains(errb.String(), "[ctxcop] redacted") {
		t.Errorf("expected redaction hint on stderr, got: %q", errb.String())
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), "\"action\":\"redacted\"") {
		t.Errorf("expected redacted audit entry, got: %q", string(data))
	}
}

func TestRunStreamingRedacts(t *testing.T) {
	var out, errb bytes.Buffer
	code, err := RunStreaming(context.Background(),
		[]string{"sh", "-c", "echo " + awsKey + "; echo plain"}, &out, &errb)
	if err != nil || code != 0 {
		t.Fatalf("RunStreaming: code=%d err=%v", code, err)
	}
	if strings.Contains(out.String(), awsKey) {
		t.Errorf("secret leaked: %q", out.String())
	}
	if !strings.Contains(out.String(), "plain") {
		t.Errorf("non-secret line dropped: %q", out.String())
	}
}
