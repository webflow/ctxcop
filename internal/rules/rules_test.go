package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

func TestLoadDetectorIncludesEmbeddedRules(t *testing.T) {
	Reset()
	t.Setenv("CTXCOP_RULES", "")
	t.Setenv("CTXCOP_DISABLE_RULES", "")
	// Point HOME at an empty dir so user files don't interfere.
	testenv.SetHomeDir(t, t.TempDir())

	list, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantIDs := []string{
		"ctxcop-aws-access-key",
		"ctxcop-github-pat-classic",
		"ctxcop-github-pat-finegrained",
		"ctxcop-stripe-secret-key",
		"ctxcop-slack-token",
	}
	have := map[string]Source{}
	for _, r := range list {
		have[r.ID] = r.Source
	}
	for _, id := range wantIDs {
		src, ok := have[id]
		if !ok {
			t.Errorf("missing embedded rule %q", id)
			continue
		}
		if src != SrcEmbedded {
			t.Errorf("rule %q has source %q want %q", id, src, SrcEmbedded)
		}
	}
}

func TestDisableRulesRemovesRule(t *testing.T) {
	Reset()
	testenv.SetHomeDir(t, t.TempDir())
	t.Setenv("CTXCOP_DISABLE_RULES", "ctxcop-stripe-secret-key, ctxcop-slack-token")
	t.Setenv("CTXCOP_RULES", "")
	list, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, r := range list {
		if (r.ID == "ctxcop-stripe-secret-key" || r.ID == "ctxcop-slack-token") && !r.Disabled {
			t.Errorf("rule %q should be marked disabled", r.ID)
		}
	}
}

func TestUserRulesLoaded(t *testing.T) {
	Reset()
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	t.Setenv("CTXCOP_DISABLE_RULES", "")
	t.Setenv("CTXCOP_RULES", "")
	dir := filepath.Join(home, ".ctxcop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rule := `
title = "user-rules"
[[rules]]
id = "test-internal-token"
description = "fake test rule"
regex = '''(WBFLW_[A-Z0-9]{16})'''
keywords = ["wbflw_"]
`
	if err := os.WriteFile(filepath.Join(dir, "internal.toml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, r := range list {
		if r.ID == "test-internal-token" {
			found = true
			if r.Source != SrcUser {
				t.Errorf("source = %q want %q", r.Source, SrcUser)
			}
			if !strings.HasSuffix(r.SourcePath, "internal.toml") {
				t.Errorf("source path = %q", r.SourcePath)
			}
		}
	}
	if !found {
		t.Errorf("user rule not loaded")
	}
}

// captureStderr redirects os.Stderr to a temp file for the duration of fn
// and returns what was written. rules.load writes warnings straight to
// os.Stderr, so this is how we observe the project-override warning.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr-*")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = old }()
	fn()
	os.Stderr = old
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A project .ctxcop.toml that redefines an embedded rule and broadens
// skip_paths must (a) emit a loud warning, (b) write an audit entry, and
// (c) leave `rules list` reflecting the effective (post-override) state.
// Before the fix, recordRules skipped already-seen IDs so the override was
// silent and List() reported the stale embedded provenance.
func TestProjectOverrideWarnsAndRecordsEffectiveState(t *testing.T) {
	projectDir := t.TempDir()
	// Hostile project file: neuter the AWS rule with a never-matching dummy
	// regex and broaden skip_paths to everything.
	projectTOML := `
title = "hostile-project"
skip_paths = ["**/*", "*"]

[[rules]]
id = "ctxcop-aws-access-key"
description = "neutered"
regex = '''ZZZ_NEVER_MATCH_[0-9]{40}'''
keywords = ["zzz_never_match"]
`
	projPath := filepath.Join(projectDir, ".ctxcop.toml")
	if err := os.WriteFile(projPath, []byte(projectTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	auditLog := filepath.Join(t.TempDir(), "audit.log")

	t.Chdir(projectDir)
	testenv.SetHomeDir(t, t.TempDir())
	t.Setenv("CTXCOP_RULES", "")
	t.Setenv("CTXCOP_DISABLE_RULES", "")
	t.Setenv("CTXCOP_AUDIT_LOG", auditLog)
	Reset()

	var list []RuleInfo
	stderr := captureStderr(t, func() {
		var err error
		list, err = List()
		if err != nil {
			t.Fatalf("List: %v", err)
		}
	})

	if !strings.Contains(stderr, "WARNING") {
		t.Errorf("expected a WARNING on project override, stderr = %q", stderr)
	}
	if !strings.Contains(stderr, "ctxcop-aws-access-key") {
		t.Errorf("warning should name the overridden rule, stderr = %q", stderr)
	}
	if !strings.Contains(stderr, "skip_paths") {
		t.Errorf("warning should mention broadened skip_paths, stderr = %q", stderr)
	}
	if !strings.Contains(stderr, projPath) {
		t.Errorf("warning should name the project file %q, stderr = %q", projPath, stderr)
	}

	var got *RuleInfo
	for i := range list {
		if list[i].ID == "ctxcop-aws-access-key" {
			got = &list[i]
		}
	}
	if got == nil {
		t.Fatal("ctxcop-aws-access-key missing from effective ruleset")
	}
	if got.Source != SrcProject {
		t.Errorf("effective source = %q, want %q (rules list must not report pre-override state)", got.Source, SrcProject)
	}
	if !got.Overridden {
		t.Error("overridden rule should be flagged Overridden=true")
	}
	if got.OverriddenFrom != SrcEmbedded {
		t.Errorf("OverriddenFrom = %q, want %q", got.OverriddenFrom, SrcEmbedded)
	}

	data, err := os.ReadFile(auditLog)
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	if !strings.Contains(string(data), "project-config-override") {
		t.Errorf("audit log missing project-config-override entry: %s", data)
	}
}

// User-scope overrides (~/.ctxcop) are operator-controlled and trusted, so
// they must NOT trigger the project-override warning — only the untrusted
// project cwd-walk does. Provenance is still updated to reflect the override.
func TestUserScopeOverrideDoesNotWarn(t *testing.T) {
	// cwd with no project config, so only user-scope is in play.
	t.Chdir(t.TempDir())
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	t.Setenv("CTXCOP_RULES", "")
	t.Setenv("CTXCOP_DISABLE_RULES", "")
	t.Setenv("CTXCOP_AUDIT_LOG", "")

	dir := filepath.Join(home, ".ctxcop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	userTOML := `
title = "user-override"
[[rules]]
id = "ctxcop-slack-token"
description = "user redefinition"
regex = '''ZZZ_NEVER_MATCH_[0-9]{40}'''
keywords = ["zzz_never_match"]
`
	if err := os.WriteFile(filepath.Join(dir, "override.toml"), []byte(userTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	Reset()

	var list []RuleInfo
	stderr := captureStderr(t, func() {
		var err error
		list, err = List()
		if err != nil {
			t.Fatalf("List: %v", err)
		}
	})

	if strings.Contains(stderr, "WARNING") || strings.Contains(stderr, "project-config-override") {
		t.Errorf("user-scope override must not trigger project warning, stderr = %q", stderr)
	}

	var got *RuleInfo
	for i := range list {
		if list[i].ID == "ctxcop-slack-token" {
			got = &list[i]
		}
	}
	if got == nil {
		t.Fatal("ctxcop-slack-token missing")
	}
	if got.Source != SrcUser {
		t.Errorf("effective source = %q, want %q", got.Source, SrcUser)
	}
	if !got.Overridden || got.OverriddenFrom != SrcEmbedded {
		t.Errorf("user override should update provenance: Overridden=%v OverriddenFrom=%q", got.Overridden, got.OverriddenFrom)
	}
}

func TestBadUserRuleFallsBackToDefaults(t *testing.T) {
	Reset()
	home := t.TempDir()
	testenv.SetHomeDir(t, home)
	t.Setenv("CTXCOP_DISABLE_RULES", "")
	t.Setenv("CTXCOP_RULES", "")
	dir := filepath.Join(home, ".ctxcop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Invalid regex (repeat count > 1000 — same trap that bit us in dev).
	bad := `
title = "bad-rule"
[[rules]]
id = "broken"
description = "uncompilable"
regex = '''[A-Z]{0,9999}'''
keywords = ["x"]
`
	if err := os.WriteFile(filepath.Join(dir, "bad.toml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDetector()
	if err != nil {
		t.Fatalf("LoadDetector returned err instead of recovering: %v", err)
	}
	if d == nil {
		t.Fatal("detector nil after recovery")
	}
}
