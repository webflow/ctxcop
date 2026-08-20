package securetemp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

func TestParentCreatesPrivateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows synthesizes 0777 for every directory, so the group/other-write check always trips and Parent() always errors; Dir()'s per-invocation fallback is the permanent Windows path")
	}
	testenv.SetTempDir(t, t.TempDir())
	p, err := Parent()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("parent perm = %#o, want 0700", fi.Mode().Perm())
	}
}

func TestParentIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows synthesizes 0777 for every directory, so the group/other-write check always trips and Parent() always errors; Dir()'s per-invocation fallback is the permanent Windows path")
	}
	testenv.SetTempDir(t, t.TempDir())
	first, err := Parent()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parent()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if first != second {
		t.Errorf("got %q then %q", first, second)
	}
}

// The #82 attack: another local user pre-plants the shared parent as a symlink,
// redirecting every redacted copy into a directory they control.
func TestParentRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation on windows")
	}
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	attacker := filepath.Join(tmp, "attacker-controlled")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attacker, filepath.Join(tmp, DirName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parent(); err == nil {
		t.Fatal("accepted a symlinked parent")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParentRejectsWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	p := filepath.Join(tmp, DirName)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: umask would mask the mode passed to Mkdir.
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Parent(); err == nil {
		t.Fatal("accepted a world-writable parent")
	}
}

func TestParentAcceptsGroupOtherReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	p := filepath.Join(tmp, DirName)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	// 0755 is what a default umask yields; readable is fine, writable is not.
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Parent(); err != nil {
		t.Errorf("rejected a non-writable 0755 parent: %v", err)
	}
}

func TestParentRejectsNonDirectory(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	if err := os.WriteFile(filepath.Join(tmp, DirName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parent(); err == nil {
		t.Fatal("accepted a regular file as the parent")
	}
}

func TestDirUsesSharedParentWhenSafe(t *testing.T) {
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	d, err := Dir("redact-*")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// Parent() always errors on windows (see TestParentCreatesPrivateDir),
		// so Dir() always takes the fallback, never the shared parent.
		if filepath.Dir(d) != tmp {
			t.Errorf("fallback %q not directly under TMPDIR %q", d, tmp)
		}
		return
	}
	if want := filepath.Join(tmp, DirName); filepath.Dir(d) != want {
		t.Errorf("dir %q not under shared parent %q", d, want)
	}
}

// Redaction must keep working when the shared parent is hostile. Callers treat
// an error as "skip redaction" and pass the original file through, so failing
// closed here would leak the raw secret.
func TestDirFallsBackWhenParentUnsafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation on windows")
	}
	tmp := t.TempDir()
	testenv.SetTempDir(t, tmp)
	attacker := filepath.Join(tmp, "attacker-controlled")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attacker, filepath.Join(tmp, DirName)); err != nil {
		t.Fatal(err)
	}

	d, err := Dir("redact-*")
	if err != nil {
		t.Fatalf("fell closed on a hostile parent: %v", err)
	}
	if strings.HasPrefix(d, attacker) {
		t.Errorf("fallback landed inside the attacker's directory: %q", d)
	}
	if filepath.Dir(d) != tmp {
		t.Errorf("fallback %q not directly under TMPDIR %q", d, tmp)
	}
	if fi, err := os.Lstat(d); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("fallback perm = %#o, want 0700", fi.Mode().Perm())
	}
}
