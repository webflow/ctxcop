package aider

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/webflow/ctxcop/internal/shellwrap"
	"github.com/webflow/ctxcop/internal/testenv"
)

// TestInstallCreatesConfigAndPrimingFile is the happy-path smoke test:
// fresh HOME, no existing .aider.conf.yml. Install should create the
// config with a `read:` entry pointing at the priming file, and write
// the priming file itself.
func TestInstallCreatesConfigAndPrimingFile(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)

	var out bytes.Buffer
	path, err := Install("user", &out)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("", ".aider.conf.yml")) {
		t.Errorf("unexpected config path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	tree := map[string]any{}
	if err := yaml.Unmarshal(data, &tree); err != nil {
		t.Fatalf("config not valid YAML: %v\n%s", err, string(data))
	}
	primingPath, _ := PrimingPath()
	entries := normalizeStringList(tree["read"])
	found := false
	for _, e := range entries {
		if e == primingPath {
			found = true
		}
	}
	if !found {
		t.Errorf("read entry missing priming path: %v", entries)
	}
	if _, err := os.Stat(primingPath); err != nil {
		t.Errorf("priming file not written: %v", err)
	}
	report := out.String()
	if !strings.Contains(report, "installed Aider config integration") {
		t.Errorf("install report missing headline: %q", report)
	}
	if !strings.Contains(report, "no lint-cmd configured") {
		t.Errorf("install should warn on missing lint-cmd: %q", report)
	}
}

// TestInstallWrapsLintCmdAndTestCmd verifies the load-bearing behavior:
// existing lint-cmd and test-cmd values get wrapped through
// `<self> run -- bash -c '<original>'` so their output flows through
// the redactor before reaching Aider (and by extension, the model).
func TestInstallWrapsLintCmdAndTestCmd(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	existing := `
lint-cmd:
  - "python: ruff check"
  - "go: golangci-lint run"
test-cmd: pytest -x
model: sonnet
`
	if err := os.WriteFile(target, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(target)
	tree := map[string]any{}
	if err := yaml.Unmarshal(data, &tree); err != nil {
		t.Fatalf("YAML: %v\n%s", err, string(data))
	}
	lints := normalizeStringList(tree["lint-cmd"])
	if len(lints) != 2 {
		t.Fatalf("expected 2 lint entries, got %d: %v", len(lints), lints)
	}
	self := shellwrap.SelfPath()
	inner, streaming, ok := unwrapAndParse(t, lints[0], self)
	if !ok || streaming {
		t.Fatalf("lint entry not a wrapped (non-streaming) entry: %q", lints[0])
	}
	if inner != "ruff check" {
		t.Errorf("lint entry command mismatch: %q", inner)
	}
	if !strings.HasPrefix(lints[0], "python: ") {
		t.Errorf("language prefix lost: %q", lints[0])
	}
	tc, _ := tree["test-cmd"].(string)
	tcInner, tcStreaming, ok := parseWrap(tc, self)
	if !ok || !tcStreaming || tcInner != "pytest -x" {
		t.Errorf("test-cmd not wrapped correctly: %q", tc)
	}
	if got, _ := tree["model"].(string); got != "sonnet" {
		t.Errorf("unrelated key clobbered: model=%q (want sonnet)", got)
	}
}

// mustSymlink creates a symlink at link pointing to target and skips
// the test if the environment can't actually honor it. Some
// environments (observed running Windows binaries under Wine) let
// os.Symlink report success while the resulting path isn't openable
// as a symlink at all — os.Lstat immediately fails to find it. Since
// that means the OS-level protection this test exercises was never
// engaged, skipping is more honest than a false pass or a false fail.
func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Skipf("os.Symlink reported success but the result isn't a usable symlink (err=%v)", err)
	}
}

// chdir switches to dir for the duration of the test and restores the
// original working directory on cleanup. Windows refuses to remove a
// directory that is any process's current directory (Unix allows it),
// so a test that os.Chdir's into a t.TempDir() and never switches back
// leaves that directory permanently busy — t.TempDir()'s own cleanup
// then fails with "sharing violation" on Windows, even though the test
// body itself passed.
func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(orig)
	})
}

// unwrapAndParse is a test helper: splits a possibly language-prefixed
// entry and parses the wrap on its command side.
func unwrapAndParse(t *testing.T, entry, self string) (inner string, streaming, ok bool) {
	t.Helper()
	_, cmd, hasLang := splitLangPrefix(entry)
	if hasLang {
		return parseWrap(cmd, self)
	}
	return parseWrap(entry, self)
}

// TestInstallPreservesUnrelatedYAML asserts that arbitrary user keys
// survive the round-trip.
func TestInstallPreservesUnrelatedYAML(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	existing := `
model: opus
auto-commits: false
weak-model: haiku
architect: true
`
	if err := os.WriteFile(target, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, _ := os.ReadFile(target)
	tree := map[string]any{}
	if err := yaml.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	if tree["model"] != "opus" {
		t.Errorf("model lost: %v", tree["model"])
	}
	if tree["auto-commits"] != false {
		t.Errorf("auto-commits lost: %v", tree["auto-commits"])
	}
	if tree["weak-model"] != "haiku" {
		t.Errorf("weak-model lost: %v", tree["weak-model"])
	}
	if tree["architect"] != true {
		t.Errorf("architect lost: %v", tree["architect"])
	}
}

// TestInstallIsIdempotent asserts that re-running install after a
// successful install produces the same file — no double-wrapped
// lint-cmds, no duplicated `read:` entries — and that the second run's
// report says the config is already wrapped rather than falsely
// claiming no lint-cmd/test-cmd is configured (the counter in the old
// implementation only tracked NEWLY wrapped entries, so a fully
// idempotent re-install reported "no lint-cmd / test-cmd found" even
// though both were correctly wrapped).
func TestInstallIsIdempotent(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	existing := `
lint-cmd: "python: ruff check"
test-cmd: pytest
`
	if err := os.WriteFile(target, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(target)
	out.Reset()
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(target)
	if string(first) != string(second) {
		t.Errorf("install not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	report := out.String()
	if !strings.Contains(report, "already wrapped") {
		t.Errorf("idempotent re-install should report already-wrapped, got: %q", report)
	}
	if strings.Contains(report, "no lint-cmd") {
		t.Errorf("idempotent re-install should not claim lint-cmd is missing: %q", report)
	}

	tree := map[string]any{}
	_ = yaml.Unmarshal(second, &tree)
	lints := normalizeStringList(tree["lint-cmd"])
	if len(lints) != 1 {
		t.Fatalf("lint-cmd doubled: %v", lints)
	}
	self := shellwrap.SelfPath()
	if strings.Count(lints[0], self) != 1 {
		t.Errorf("lint-cmd double-wrapped: %q", lints[0])
	}
	tc, _ := tree["test-cmd"].(string)
	if strings.Count(tc, self) != 1 {
		t.Errorf("test-cmd double-wrapped: %q", tc)
	}
	primingPath, _ := PrimingPath()
	reads := normalizeStringList(tree["read"])
	seen := 0
	for _, r := range reads {
		if r == primingPath {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("priming path appeared %d times in read (want 1): %v", seen, reads)
	}
}

// TestInstallWarnsOnMissingLintCmdEvenWithTestCmdSet is the regression
// test for Andrew's point that the warning only fired when BOTH
// lint-cmd and test-cmd were absent, even though the documented
// behavior (docs/harnesses.md, docs/known-limits.md) is that the
// warning covers lint-cmd's auto-detected-linter bypass specifically.
func TestInstallWarnsOnMissingLintCmdEvenWithTestCmdSet(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	if err := os.WriteFile(target, []byte("test-cmd: pytest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no lint-cmd configured") {
		t.Errorf("expected lint-cmd warning even with test-cmd set, got: %q", out.String())
	}
}

// TestInstallRefusesToWriteThroughSymlink is the regression test for
// Cursor's HIGH-severity finding: os.WriteFile follows symlinks, so a
// repo-controlled symlink at .aider.conf.yml could redirect ctxcop's
// write to an arbitrary path outside the workspace.
func TestInstallRefusesToWriteThroughSymlink(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	outsideTarget := filepath.Join(t.TempDir(), "victim.yml")
	if err := os.WriteFile(outsideTarget, []byte("untouched: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outsideTarget, target)
	var out bytes.Buffer
	if _, err := Install("user", &out); err == nil {
		t.Fatal("expected Install to refuse writing through a symlink")
	}
	data, _ := os.ReadFile(outsideTarget)
	if string(data) != "untouched: true\n" {
		t.Errorf("symlink target was modified: %q", data)
	}
}

// TestUninstallRefusesToWriteThroughSymlink mirrors the Install case
// for the uninstall path.
func TestUninstallRefusesToWriteThroughSymlink(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	outsideTarget := filepath.Join(t.TempDir(), "victim.yml")
	// Needs an actual ctxcop wrap so Uninstall finds something to
	// remove and reaches the write path at all — a lint-cmd value that
	// merely looks wrapped is correctly left alone (nothing to write),
	// which would make this test pass vacuously.
	wrapped, _ := wrapEntry(shellwrap.SelfPath(), false, "ruff check")
	existing := "lint-cmd: " + string(mustYAML(t, wrapped)) + "\n"
	if err := os.WriteFile(outsideTarget, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outsideTarget, target)
	var out bytes.Buffer
	if _, _, err := Uninstall("user", &out); err == nil {
		t.Fatal("expected Uninstall to refuse writing through a symlink")
	}
}

// mustYAML renders v as a YAML scalar (quoting as needed) for
// hand-building test fixture files.
func mustYAML(t *testing.T, v string) []byte {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimRight(b, "\n")
}

// TestInstallAbortsOnUnreadableExistingConfig is the regression test
// for Andrew's point that an unreadable (permission-denied) existing
// config was silently overwritten with a fresh empty tree instead of
// aborting — the old code only distinguished "read succeeded" from
// "anything else", treating a permission error the same as "file
// doesn't exist yet".
func TestInstallAbortsOnUnreadableExistingConfig(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	if runtime.GOOS == "windows" {
		// os.Chmod on Windows only toggles the read-only attribute (the
		// 0o200 bit) — it cannot make a file unreadable to its owner, so
		// this test's precondition is unreachable on that platform.
		t.Skip("os.Chmod cannot simulate a permission-denied read on Windows")
	}
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	if err := os.WriteFile(target, []byte("model: opus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(target, 0o644)

	var out bytes.Buffer
	if _, err := Install("user", &out); err == nil {
		t.Fatal("expected Install to abort on an unreadable existing config")
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "model: opus\n" {
		t.Errorf("unreadable config was overwritten: %q", data)
	}
}

// TestUninstallRestoresOriginalCommandsAndRemovesPrimingRef verifies
// the round-trip: install then uninstall gets back to a config
// equivalent to the original.
func TestUninstallRestoresOriginalCommandsAndRemovesPrimingRef(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	target := filepath.Join(home, ".aider.conf.yml")
	existing := `
lint-cmd:
  - "python: ruff check"
  - "go: golangci-lint run"
test-cmd: pytest -x
model: sonnet
`
	if err := os.WriteFile(target, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_, removed, err := Uninstall("user", &out)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if removed < 3 {
		t.Errorf("expected >=3 removals (2 lint + 1 test + 1 read entry), got %d", removed)
	}

	data, _ := os.ReadFile(target)
	tree := map[string]any{}
	if err := yaml.Unmarshal(data, &tree); err != nil {
		t.Fatalf("post-uninstall not valid YAML: %v\n%s", err, string(data))
	}
	lints := normalizeStringList(tree["lint-cmd"])
	for _, e := range lints {
		if strings.Contains(e, "run --") {
			t.Errorf("lint entry still wrapped: %q", e)
		}
	}
	tc, _ := tree["test-cmd"].(string)
	if strings.Contains(tc, "run --") {
		t.Errorf("test-cmd still wrapped: %q", tc)
	}
	primingPath, _ := PrimingPath()
	for _, r := range normalizeStringList(tree["read"]) {
		if r == primingPath {
			t.Errorf("priming path still referenced after uninstall: %v", r)
		}
	}
	if _, err := os.Stat(primingPath); !os.IsNotExist(err) {
		t.Errorf("priming file still exists after uninstall: %v", err)
	}
	if tree["model"] != "sonnet" {
		t.Errorf("unrelated key lost: model=%v", tree["model"])
	}
}

// TestUninstallPreservesSharedPrimingFileForOtherScope is the
// regression test for Andrew's point that uninstalling one scope
// (project vs. user) deleted the shared ~/.aider/ctxcop-priming.md
// file outright, leaving the OTHER scope's config pointing at a
// now-missing file.
func TestUninstallPreservesSharedPrimingFileForOtherScope(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	testenv.SetHomeDir(t, home)
	chdir(t, cwd)

	var out bytes.Buffer
	if _, err := Install("user", &out); err != nil {
		t.Fatalf("user install: %v", err)
	}
	out.Reset()
	if _, err := Install("project", &out); err != nil {
		t.Fatalf("project install: %v", err)
	}

	primingPath, _ := PrimingPath()
	if _, err := os.Stat(primingPath); err != nil {
		t.Fatalf("priming file missing before uninstall: %v", err)
	}

	out.Reset()
	if _, _, err := Uninstall("project", &out); err != nil {
		t.Fatalf("project uninstall: %v", err)
	}
	if _, err := os.Stat(primingPath); err != nil {
		t.Errorf("priming file removed while user scope still references it: %v", err)
	}

	out.Reset()
	if _, _, err := Uninstall("user", &out); err != nil {
		t.Fatalf("user uninstall: %v", err)
	}
	if _, err := os.Stat(primingPath); !os.IsNotExist(err) {
		t.Errorf("priming file should be gone once neither scope references it: %v", err)
	}
}

// TestUninstallNoFileIsNoop mirrors the other adapters' contract:
// missing config file is a no-op success.
func TestUninstallNoFileIsNoop(t *testing.T) {
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	var out bytes.Buffer
	_, removed, err := Uninstall("user", &out)
	if err != nil || removed != 0 {
		t.Errorf("missing config should be no-op success, got removed=%d err=%v", removed, err)
	}
}

// TestInstallProjectScopeWritesToCwd asserts the project scope writes
// to the current directory, not $HOME. Path comparison resolves
// symlinks — on macOS t.TempDir() returns /var/… which resolves to
// /private/var/…, and cwd fetched via os.Getwd() picks up the
// resolved form.
func TestInstallProjectScopeWritesToCwd(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	testenv.SetHomeDir(t, home)
	chdir(t, cwd)
	var out bytes.Buffer
	path, err := Install("project", &out)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	realCwd, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatal(err)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(realPath, realCwd) {
		t.Errorf("project scope wrote outside cwd: %q (cwd=%q)", realPath, realCwd)
	}
	// Belt-and-suspenders: make sure it's the config file we expect
	// and it wasn't written under $HOME.
	if filepath.Base(path) != ".aider.conf.yml" {
		t.Errorf("unexpected basename: %s", path)
	}
	realHome, _ := filepath.EvalSymlinks(home)
	if realHome != "" && strings.HasPrefix(realPath, realHome) {
		t.Errorf("project scope leaked into $HOME: %q (home=%q)", realPath, realHome)
	}
}

// TestSettingsPathUnknownScope covers the error branch.
func TestSettingsPathUnknownScope(t *testing.T) {
	if _, err := SettingsPath("system"); err == nil {
		t.Error("unknown scope should error")
	}
}
