package pause

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webflow/ctxcop/internal/testenv"
)

// TestIsPausedSentinel exercises the three states callers depend on:
// absent, future-expiry, past-expiry. Was previously in claudecode's
// skip_test.go before pause-state moved into this package.
func TestIsPausedSentinel(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetHomeDir(t, tmp)
	dir := filepath.Join(tmp, ".ctxcop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if IsPaused() {
		t.Errorf("paused before sentinel exists")
	}
	// Future expiry → paused.
	exp := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "paused"), []byte(exp), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsPaused() {
		t.Errorf("future-expiry sentinel not detected as paused")
	}
	// Past expiry → not paused.
	exp = time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "paused"), []byte(exp), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsPaused() {
		t.Errorf("expired sentinel still treated as paused")
	}
}

// TestIsPausedMalformedSentinel: a corrupt sentinel is treated as
// paused-indefinite so the user has a clear "ctxcop status" signal to
// run `ctxcop resume` from. This is a deliberate fail-open-on-decision
// trade-off documented in the audit.
func TestIsPausedMalformedSentinel(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetHomeDir(t, tmp)
	dir := filepath.Join(tmp, ".ctxcop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "paused"), []byte("not-a-timestamp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsPaused() {
		t.Errorf("malformed sentinel should be treated as paused-indefinite")
	}
}

func TestRemaining(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetHomeDir(t, tmp)
	dir := filepath.Join(tmp, ".ctxcop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := Remaining(); got != 0 {
		t.Errorf("Remaining with no sentinel = %v, want 0", got)
	}
	exp := time.Now().Add(45 * time.Minute).Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "paused"), []byte(exp), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Remaining()
	if got < 44*time.Minute || got > 46*time.Minute {
		t.Errorf("Remaining = %v, want ~45m", got)
	}
	// Expired sentinel reports 0, not a negative duration.
	exp = time.Now().Add(-5 * time.Minute).Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(dir, "paused"), []byte(exp), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Remaining(); got != 0 {
		t.Errorf("Remaining for expired sentinel = %v, want 0", got)
	}
}

func TestPauseResumeStatus(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetHomeDir(t, tmp)

	var buf bytes.Buffer
	if err := Pause("10m", &buf); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if !strings.Contains(buf.String(), "paused until") {
		t.Errorf("Pause output missing 'paused until': %q", buf.String())
	}
	if !IsPaused() {
		t.Errorf("IsPaused false after Pause")
	}

	buf.Reset()
	if err := Status(&buf); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.Contains(buf.String(), "paused for") {
		t.Errorf("Status output should say 'paused for': %q", buf.String())
	}

	buf.Reset()
	if err := Resume(&buf); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if IsPaused() {
		t.Errorf("IsPaused true after Resume")
	}

	// Resume is idempotent.
	if err := Resume(&buf); err != nil {
		t.Errorf("Resume idempotent failure: %v", err)
	}
}

func TestComputeExpiryDefaults(t *testing.T) {
	now := time.Now()
	exp, err := computeExpiry("")
	if err != nil {
		t.Fatalf("computeExpiry default: %v", err)
	}
	if d := exp.Sub(now); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("default duration = %v, want ~1h", d)
	}
	exp, err = computeExpiry("indefinite")
	if err != nil {
		t.Fatalf("computeExpiry indefinite: %v", err)
	}
	if exp.Sub(now) < 360*24*time.Hour {
		t.Errorf("indefinite duration too short: %v", exp.Sub(now))
	}
	if _, err := computeExpiry("garbage"); err == nil {
		t.Errorf("expected error for garbage duration")
	}
	if _, err := computeExpiry("-5m"); err == nil {
		t.Errorf("expected error for negative duration")
	}
}
