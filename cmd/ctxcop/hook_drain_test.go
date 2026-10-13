package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A paused hook returns before reading stdin. Every harness bridge must
// still be able to write a payload larger than the pipe buffer without
// EPIPE, so the binary has to drain stdin before exiting.
func TestPausedHooksDrainStdin(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "ctxcop")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ctxcop"), 0o700); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(home, ".ctxcop", "paused"), []byte(expiry), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"payload":"` + strings.Repeat("x", 400*1024) + `"}`

	events := [][]string{
		{"pre-tool-use"}, {"post-tool-use"}, {"pre-compact"}, {"post-compact"},
		{"elicitation-result"}, {"session-start"},
		{"codex", "pre-tool-use"}, {"codex", "post-tool-use"},
		{"cursor", "pre-tool-use"}, {"cursor", "post-tool-use"},
		{"pi", "before-provider-request"}, {"pi", "before-agent-start"}, {"pi", "tool-call"},
		{"opencode", "tool-execute-before"}, {"opencode", "tool-execute-after"},
	}
	for _, ev := range events {
		t.Run(strings.Join(ev, "/"), func(t *testing.T) {
			cmd := exec.Command(bin, append([]string{"hook"}, ev...)...)
			cmd.Env = append(os.Environ(), "HOME="+home)
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// exec.Cmd.Stdin hides EPIPE, so write directly and check it.
			if _, err := io.WriteString(in, body); err != nil {
				t.Errorf("write to hook stdin: %v", err)
			}
			in.Close()
			if err := cmd.Wait(); err != nil {
				t.Errorf("exit: %v", err)
			}
		})
	}
}
