package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/webflow/ctxcop/internal/audit"
)

// RunStreaming is like Run but emits redacted output line-by-line as the
// child produces it. Tradeoff: a credential split across newlines would be
// missed (each line is redacted independently). Use for background commands
// where the agent reads via BashOutput while the child still runs.
func RunStreaming(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error) {
	if len(argv) == 0 {
		return 2, errors.New("ctxcop: no command")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 127, err
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return 127, err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("ctxcop: start %q: %w", argv[0], err)
	}

	go func() {
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

	// Accumulate the rule IDs redacted across the whole stream so end-of-stream
	// can emit the hint and write an audit entry, mirroring the buffered Run
	// path (issue #58 — a streamed redaction was previously a silent drop).
	var (
		mu       sync.Mutex
		allRules []string
	)
	collect := func(rules []string) {
		if len(rules) == 0 {
			return
		}
		mu.Lock()
		allRules = append(allRules, rules...)
		mu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go pump(&wg, outPipe, stdout, collect)
	go pump(&wg, errPipe, stderr, collect)
	wg.Wait()

	// End-of-stream reporting. NOTE: each line is scanned independently (see
	// pump), so a secret split across a newline still evades this per-line scan
	// — a documented limitation of streaming, left as-is.
	if rules := dedupe(allRules, nil); len(rules) > 0 {
		_, _ = io.WriteString(stderr, buildHint(rules, nil))
		audit.Log(audit.Entry{Tool: "Bash", Action: "redacted", Rules: rules})
	}

	waitErr := cmd.Wait()
	return exitCodeOf(cmd, waitErr), nil
}

func pump(wg *sync.WaitGroup, r io.Reader, w io.Writer, collect func([]string)) {
	defer wg.Done()
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			collect(emit(w, line))
		}
		if err != nil {
			return
		}
	}
}
