package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogOffByDefault(t *testing.T) {
	t.Setenv("CTXCOP_AUDIT_LOG", "")
	dir := t.TempDir()
	probe := filepath.Join(dir, "should-not-exist.jsonl")
	Log(Entry{Tool: "Bash", Action: "wrapped"})
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Errorf("audit log appeared without opt-in: %v", err)
	}
}

func TestLogWritesWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("CTXCOP_AUDIT_LOG", path)
	Log(Entry{Tool: "Bash", Action: "wrapped"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), `"tool":"Bash"`) {
		t.Errorf("entry not written: %q", data)
	}
}

// ---- chain ----------------------------------------------------------------

func TestLogChainsEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("CTXCOP_AUDIT_LOG", path)

	for i, action := range []string{"wrapped", "redacted", "blocked"} {
		Log(Entry{Tool: "Bash", Action: action, Count: i + 1})
	}
	entries := readEntries(t, path)
	if got := len(entries); got != 3 {
		t.Fatalf("wrote 3 entries, found %d", got)
	}
	// First entry's prev must be "" — chain root.
	if entries[0].Prev != "" {
		t.Errorf("first entry Prev should be empty, got %q", entries[0].Prev)
	}
	// Each entry's hash must be present + each subsequent prev links back.
	for i, e := range entries {
		if e.Hash == "" {
			t.Errorf("entry %d missing Hash", i)
		}
		if i > 0 && e.Prev != entries[i-1].Hash {
			t.Errorf("entry %d Prev=%q, expected %q", i, e.Prev, entries[i-1].Hash)
		}
	}
}

func TestVerifyCleanChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("CTXCOP_AUDIT_LOG", path)
	for i := 0; i < 5; i++ {
		Log(Entry{Tool: "Bash", Action: "wrapped", Count: i})
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ok() {
		t.Errorf("expected clean chain, got broken: %+v", res.Broken)
	}
	if res.Verified != 5 || res.TotalEntries != 5 {
		t.Errorf("want 5 verified of 5, got %d of %d", res.Verified, res.TotalEntries)
	}
	if res.Legacy != 0 {
		t.Errorf("no legacy entries expected, got %d", res.Legacy)
	}
}

func TestVerifyDetectsTamperedField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("CTXCOP_AUDIT_LOG", path)
	Log(Entry{Tool: "Bash", Action: "wrapped"})
	Log(Entry{Tool: "Bash", Action: "redacted"})

	// Tamper: change the middle entry's tool name without recomputing hash.
	raw, _ := os.ReadFile(path)
	tampered := bytes.Replace(raw, []byte(`"tool":"Bash","action":"redacted"`), []byte(`"tool":"Bash","action":"REDACTED"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("substitution didn't apply; can't run tamper test")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ok() {
		t.Fatal("expected broken entry; verify reported clean")
	}
	if got := res.Broken[0].Kind; got != "hash" {
		t.Errorf("expected first broken kind=hash, got %q (%s)", got, res.Broken[0].Detail)
	}
}

func TestVerifyDetectsRemovedEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t.Setenv("CTXCOP_AUDIT_LOG", path)
	for i := 0; i < 4; i++ {
		Log(Entry{Tool: "Bash", Action: "wrapped", Count: i})
	}
	// Remove the second line. The third's Prev no longer matches the
	// first's Hash → chain break.
	raw, _ := os.ReadFile(path)
	lines := bytes.Split(raw, []byte("\n"))
	keep := append(lines[:1], lines[2:]...)
	if err := os.WriteFile(path, bytes.Join(keep, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ok() {
		t.Fatal("expected chain break; verify reported clean")
	}
	if got := res.Broken[0].Kind; got != "chain" {
		t.Errorf("expected first broken kind=chain, got %q (%s)", got, res.Broken[0].Detail)
	}
}

func TestVerifyAcceptsLegacyEntries(t *testing.T) {
	// Simulate a v0.2.0-era log: entries without Prev/Hash. Verify must
	// not flag these; they should be reported as Legacy.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	legacy := `{"ts":"2026-05-01T00:00:00Z","tool":"Bash","action":"wrapped"}
{"ts":"2026-05-01T00:00:01Z","tool":"Bash","action":"redacted"}
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ok() {
		t.Errorf("legacy entries should not break verify: %+v", res.Broken)
	}
	if res.Legacy != 2 {
		t.Errorf("expected 2 legacy entries, got %d", res.Legacy)
	}
	if res.Verified != 0 {
		t.Errorf("legacy entries shouldn't count as verified, got %d", res.Verified)
	}
}

func TestLogResumesChainAfterLegacy(t *testing.T) {
	// File starts with a legacy entry. New entries via Log() must form a
	// fresh chain rooted at "" — they can't link back to a hashless line.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	legacy := `{"ts":"2026-05-01T00:00:00Z","tool":"Bash","action":"wrapped"}
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CTXCOP_AUDIT_LOG", path)
	Log(Entry{Tool: "Bash", Action: "redacted"})
	Log(Entry{Tool: "Bash", Action: "blocked"})

	entries := readEntries(t, path)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (1 legacy + 2 chained), got %d", len(entries))
	}
	if entries[1].Prev != "" {
		t.Errorf("first chained entry after legacy must restart chain with Prev=\"\", got %q", entries[1].Prev)
	}
	if entries[2].Prev != entries[1].Hash {
		t.Errorf("third entry's Prev should link to second's Hash; got %q vs %q", entries[2].Prev, entries[1].Hash)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ok() {
		t.Errorf("expected clean verify after legacy reset: %+v", res.Broken)
	}
	if res.Legacy != 1 || res.Verified != 2 {
		t.Errorf("want legacy=1, verified=2; got legacy=%d verified=%d", res.Legacy, res.Verified)
	}
}

// ---- cross-process concurrency --------------------------------------------

// TestConcurrentMultiProcessChain reproduces the real hook topology: many
// separate PROCESSES appending to one shared log at once (Claude Code runs
// tool calls, hence hooks, in parallel). The in-process sync.Mutex can't
// serialize across processes, so without a cross-process file lock two
// appenders read the same lastHash and both chain off it → verify reports a
// chain break on an honest log. Pre-fix this fails (~84/100 broken observed);
// post-fix the flock makes the read-Prev + append atomic across processes.
func TestConcurrentMultiProcessChain(t *testing.T) {
	if os.Getenv("CTXCOP_AUDIT_HELPER") == "1" {
		return // never re-enter as the parent when running as a helper child
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	const procs = 20
	const perProc = 25

	// Start-barrier: hand every child the same wall-clock start instant, a
	// bit in the future, so they clear process/runtime startup and then
	// append simultaneously. Without this, per-process startup jitter
	// serializes the short Log() windows and hides the race.
	startAt := time.Now().Add(750 * time.Millisecond).UnixNano()

	var wg sync.WaitGroup
	errs := make(chan error, procs)
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=TestAuditAppendHelper", "-test.count=1")
			cmd.Env = append(os.Environ(),
				"CTXCOP_AUDIT_HELPER=1",
				"CTXCOP_AUDIT_LOG="+path,
				fmt.Sprintf("CTXCOP_AUDIT_HELPER_N=%d", perProc),
				fmt.Sprintf("CTXCOP_AUDIT_HELPER_START=%d", startAt),
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("helper process failed: %v\n%s", err, out)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ok() {
		sample := res.Broken
		if len(sample) > 5 {
			sample = sample[:5]
		}
		t.Fatalf("concurrent appends broke the chain: %d/%d broken; first: %+v",
			len(res.Broken), res.TotalEntries, sample)
	}
	if want := procs * perProc; res.TotalEntries != want || res.Verified != want {
		t.Fatalf("want %d verified of %d, got %d of %d", want, want, res.Verified, res.TotalEntries)
	}
}

// TestAuditAppendHelper is the child-process body for
// TestConcurrentMultiProcessChain. It appends N entries to the shared log and
// exits; under a normal test run (no helper env) it skips.
func TestAuditAppendHelper(t *testing.T) {
	if os.Getenv("CTXCOP_AUDIT_HELPER") != "1" {
		t.Skip("helper subprocess only; driven by TestConcurrentMultiProcessChain")
	}
	n, _ := strconv.Atoi(os.Getenv("CTXCOP_AUDIT_HELPER_N"))
	if n <= 0 {
		n = 5
	}
	if raw := os.Getenv("CTXCOP_AUDIT_HELPER_START"); raw != "" {
		if ns, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if d := time.Until(time.Unix(0, ns)); d > 0 {
				time.Sleep(d)
			}
		}
	}
	for i := 0; i < n; i++ {
		Log(Entry{Tool: "Bash", Action: "wrapped", Count: i})
	}
}

// readEntries decodes the file as one Entry per non-empty line.
func readEntries(t *testing.T, path string) []Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []Entry
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad entry %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}
