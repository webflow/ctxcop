package aider

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

// TestPreflightWarnsOnSecretInEnv is the load-bearing assertion: the
// user runs `ctxcop hook aider preflight` before `aider`, we scan
// .env, and if it contains an AKIA-shape value we warn on stderr.
func TestPreflightWarnsOnSecretInEnv(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("AWS_ACCESS_KEY_ID="+akia+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Preflight(root, &out); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "credential-shape value") {
		t.Errorf("expected warning, got: %q", got)
	}
	if !strings.Contains(got, envPath) {
		t.Errorf("warning should name the offending path: %q", got)
	}
}

// TestPreflightSilentOnCleanEnv covers the no-warn path — nothing
// should reach stderr when the .env is clean.
func TestPreflightSilentOnCleanEnv(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("FEATURE_FLAG=true\nLOG_LEVEL=info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Preflight(root, &out); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("clean .env should be silent, got: %q", out.String())
	}
}

// TestPreflightHonorsPause guards the shared pause sentinel.
func TestPreflightHonorsPause(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	pausedDir := filepath.Join(home, ".ctxcop")
	if err := os.MkdirAll(pausedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A far-future timestamp keeps pause active for the test.
	if err := os.WriteFile(filepath.Join(pausedDir, "paused"), []byte("2099-01-01T00:00:00Z"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("AWS_ACCESS_KEY_ID="+akia+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Preflight(root, &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("paused Preflight should be silent, got: %q", out.String())
	}
}

// TestPreflightMissingRoot exits silently rather than erroring — a
// user who runs the command from a non-existent path shouldn't get
// a scary error, just no warning.
func TestPreflightMissingRoot(t *testing.T) {
	var out bytes.Buffer
	if err := Preflight("/definitely/not/a/real/path", &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("missing root should be silent, got: %q", out.String())
	}
}
