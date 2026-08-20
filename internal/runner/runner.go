package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/redact"
)

// Run executes argv, redacts secrets from captured stdout/stderr to the
// supplied writers, and returns the child's exit code (128+sig on signal
// termination). SIGINT/SIGTERM are forwarded to the child.
func Run(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error) {
	if len(argv) == 0 {
		return 2, errors.New("ctxcop: no command")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("ctxcop: start %q: %w", argv[0], err)
	}

	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		for {
			select {
			case sig := <-sigCh:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	waitErr := cmd.Wait()

	outRules := emit(stdout, outBuf.String())
	errRules := emit(stderr, errBuf.String())

	if hint := buildHint(outRules, errRules); hint != "" {
		_, _ = io.WriteString(stderr, hint)
		audit.Log(audit.Entry{Tool: "Bash", Action: "redacted", Rules: dedupe(outRules, errRules)})
	}

	return exitCodeOf(cmd, waitErr), nil
}

// emit redacts and writes; returns the rule IDs that fired. Command output is
// untrusted tool output, so it uses RedactToolOutput — inline allow/fixture
// markers in the stream (e.g. `cat .env | sed 's/$/ # ctxcop:allow/'`) must
// NOT suppress redaction (issue #56).
func emit(w io.Writer, content string) []string {
	red, rules, err := redact.RedactToolOutput(content)
	if err != nil {
		// Fail-open: pass through on detector failure.
		fmt.Fprintf(os.Stderr, "ctxcop: redact failed, passing through: %v\n", err)
		red = content
		rules = nil
	}
	if red != "" {
		_, _ = io.WriteString(w, red)
	}
	return rules
}

// buildHint emits the guidance line on stderr so it lands in the same
// tool_result the agent sees.
func buildHint(outRules, errRules []string) string {
	rules := dedupe(outRules, errRules)
	if len(rules) == 0 {
		return ""
	}
	return fmt.Sprintf("\n[ctxcop] redacted %d secret(s) (%s) before this output reached the model. "+
		"To USE the value in follow-up work, reference it via $ENV_VAR in a shell command — substitution "+
		"happens in the child shell, so the value never enters your context. Don't pipe through base64/xxd "+
		"to reveal it: that's tracked in the audit log and still bypasses your threat model.\n",
		len(rules), joinComma(rules))
}

func dedupe(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func exitCodeOf(cmd *exec.Cmd, waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return 128 + int(status.Signal())
			}
			return status.ExitStatus()
		}
		return ee.ExitCode()
	}
	return 1
}
