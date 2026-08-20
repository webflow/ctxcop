package skiplist

import "testing"

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"**/testdata/**", "src/foo/testdata/file.json", true},
		{"**/testdata/**", "src/foo/test/file.json", false},
		{"*_test.go", "internal/runner/runner_test.go", true},
		{"*_test.go", "internal/runner/runner.go", false},
		{"*.test.ts", "src/app.test.ts", true},
		{"*.test.ts", "src/app.ts", false},
		{"**/.ctxcop/**", "/home/me/.ctxcop/rules.toml", true},
		{"fixtures/**", "fixtures/keys.txt", true},
		{"fixtures/**", "fixtures", true},
		{"fixtures/**", "src/fixtures/keys.txt", true},
		{"fixtures/**", "src/fixtures", true},
		{"fixtures/**", "/abs/path/fixtures/x.json", true},
		{"fixtures/**", "src/fixturesXYZ/x.json", false},
		{"*.golden", "snapshot.golden", true},
		{"*.fixture.*", "user.fixture.json", true},
		{"main.go", "/Users/x/main.go", true},
		{"main.go", "/Users/x/lib/main.go", true},
		{"main.go", "/Users/x/main.go.bak", false},
	}
	for _, c := range cases {
		if got := matchGlob(c.pat, c.path); got != c.want {
			t.Errorf("matchGlob(%q,%q)=%v want %v", c.pat, c.path, got, c.want)
		}
	}
}

func TestShouldSkipDefaults(t *testing.T) {
	t.Setenv("CTXCOP_SKIP_PATHS", "")
	defer ResetForTest()
	cases := []struct {
		path string
		want bool
	}{
		{"internal/runner/runner_test.go", true},
		{"testdata/big.json", true},
		{"src/foo/testdata/x.txt", true},
		{"src/app.spec.ts", true},
		{"src/app.tsx", false},
		{"README.md", false},
	}
	for _, c := range cases {
		if got := ShouldSkip(c.path); got != c.want {
			t.Errorf("ShouldSkip(%q)=%v want %v", c.path, got, c.want)
		}
	}
}

func TestShouldSkipEnvAdds(t *testing.T) {
	t.Setenv("CTXCOP_SKIP_PATHS", "**/my-fixtures/**, *.sample")
	defer ResetForTest()
	if !ShouldSkip("src/my-fixtures/x.json") {
		t.Errorf("env skip pattern not honored")
	}
	if !ShouldSkip("env.sample") {
		t.Errorf("*.sample not honored")
	}
}

func TestSkipPathsFromProjectWiring(t *testing.T) {
	defer ResetForTest()
	prev := SkipPathsFromProject
	defer func() { SkipPathsFromProject = prev }()
	SkipPathsFromProject = func() []string { return []string{"my-secrets/**"} }
	ResetForTest()
	if !ShouldSkip("repo/my-secrets/prod.env") {
		t.Errorf("project skip pattern not honored")
	}
}

func TestShouldSkipEmptyPath(t *testing.T) {
	if ShouldSkip("") {
		t.Errorf("empty path should not be skipped")
	}
}
