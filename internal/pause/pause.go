package pause

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func sentinelPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ctxcop", "paused"), nil
}

// IsPaused: non-expired sentinel exists. Malformed sentinel = paused
// indefinitely (until `ctxcop resume`) — fail-closed-on-corruption.
func IsPaused() bool {
	path, err := sentinelPath()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	expiry, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return true
	}
	return time.Now().Before(expiry)
}

// Banner returns a one-line paused notice or "" when active. Callers can
// unconditionally invoke and gate on empty.
func Banner() string {
	if !IsPaused() {
		return ""
	}
	r := Remaining()
	if r == 0 {
		return "[ctxcop] PAUSED indefinitely (malformed sentinel) — hooks are passthrough, no redaction or blocks. Run `ctxcop resume` to re-enable."
	}
	if r > 364*24*time.Hour {
		return "[ctxcop] PAUSED (indefinite) — hooks are passthrough, no redaction or blocks. Run `ctxcop resume` to re-enable."
	}
	return fmt.Sprintf("[ctxcop] PAUSED — hooks are passthrough, no redaction or blocks (%s remaining). Run `ctxcop resume` to re-enable.", r.Round(time.Second))
}

// Remaining returns time-until-expiry, or 0 if not paused / malformed.
func Remaining() time.Duration {
	path, err := sentinelPath()
	if err != nil {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	expiry, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	d := time.Until(expiry)
	if d < 0 {
		return 0
	}
	return d
}

// Pause writes a sentinel with an expiry. durStr is a Go duration
// (10m, 2h, 30s) or "indefinite"/"forever".
func Pause(durStr string, w io.Writer) error {
	expiry, err := computeExpiry(durStr)
	if err != nil {
		return err
	}
	path, err := sentinelPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(expiry.Format(time.RFC3339)), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(w, "ctxcop: paused until %s (%s from now)\n",
		expiry.Format(time.RFC3339), time.Until(expiry).Truncate(time.Second))
	return nil
}

// Resume removes the sentinel. Idempotent.
func Resume(w io.Writer) error {
	path, err := sentinelPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintln(w, "ctxcop: resumed")
	return nil
}

func Status(w io.Writer) error {
	path, err := sentinelPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w, "ctxcop: active")
		return nil
	}
	if err != nil {
		return err
	}
	expiry, perr := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if perr != nil {
		fmt.Fprintln(w, "ctxcop: paused (indefinite — sentinel is malformed; `ctxcop resume` to clear)")
		return nil
	}
	if time.Now().After(expiry) {
		fmt.Fprintf(w, "ctxcop: active (pause expired at %s; sentinel file lingers, harmless)\n",
			expiry.Format(time.RFC3339))
		return nil
	}
	fmt.Fprintf(w, "ctxcop: paused for %s more (until %s)\n",
		time.Until(expiry).Truncate(time.Second), expiry.Format(time.RFC3339))
	return nil
}

func computeExpiry(durStr string) (time.Time, error) {
	now := time.Now()
	if durStr == "" {
		return now.Add(1 * time.Hour), nil
	}
	if strings.EqualFold(durStr, "indefinite") || strings.EqualFold(durStr, "forever") {
		return now.Add(365 * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(durStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --for value %q: expected Go duration (e.g. 10m, 2h, 30s) or `indefinite`", durStr)
	}
	if d <= 0 {
		return time.Time{}, fmt.Errorf("--for must be positive, got %s", d)
	}
	return now.Add(d), nil
}
