package claudecode

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webflow/ctxcop/internal/testenv"
)

func TestSessionEndRemovesOwnFiles(t *testing.T) {
	dir := t.TempDir()
	testenv.SetTempDir(t, dir)
	cdir := filepath.Join(dir, "ctxcop")
	if err := os.MkdirAll(cdir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Our artifacts are now per-invocation subdirectories ("redact-<random>")
	// each holding a redacted copy — not bare files.
	ours := filepath.Join(cdir, "redact-abc123")
	if err := os.MkdirAll(ours, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ours, "creds.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	notOurs := filepath.Join(cdir, "user-stashed.txt")
	if err := os.WriteFile(notOurs, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := SessionEnd(&out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough json, got %q", got)
	}
	if _, err := os.Stat(ours); !os.IsNotExist(err) {
		t.Errorf("own dir not removed: %v", err)
	}
	if _, err := os.Stat(notOurs); err != nil {
		t.Errorf("unrelated file removed: %v", err)
	}
}

func TestSessionEndMissingDir(t *testing.T) {
	dir := t.TempDir()
	testenv.SetTempDir(t, dir)
	var out bytes.Buffer
	if err := SessionEnd(&out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough when dir missing, got %q", got)
	}
}

func TestLooksLikeOurTemp(t *testing.T) {
	cases := map[string]bool{
		"redact-abc123":      true,
		"redact-0":           true,
		"redact-":            false, // prefix only, no random suffix
		"redact":             false,
		"user-stashed.txt":   false,
		"0123456789abcdef_x": false, // old scheme is no longer ours
		"":                   false,
	}
	for name, want := range cases {
		if got := looksLikeOurTemp(name); got != want {
			t.Errorf("looksLikeOurTemp(%q)=%v want %v", name, got, want)
		}
	}
}

func TestSessionEndOldFilesGetCleaned(t *testing.T) {
	dir := t.TempDir()
	testenv.SetTempDir(t, dir)
	cdir := filepath.Join(dir, "ctxcop")
	if err := os.MkdirAll(cdir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(cdir, "redact-feedface")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "old.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Push mtime well into the past — older than the cutoff.
	past := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(old, past, past)

	var out bytes.Buffer
	if err := SessionEnd(&out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old own dir not removed: %v", err)
	}
}
