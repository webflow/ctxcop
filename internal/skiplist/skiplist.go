// Package skiplist tells harness adapters which file paths should bypass
// scanning. Three sources OR'd: defaults below, $CTXCOP_SKIP_PATHS env,
// and skip_paths injected by main from a discovered .ctxcop.toml.
//
// Pattern matcher (tiny; not a full glob library):
//
//	"**/X/**"  → path contains "/X/" as a directory segment
//	"**/X"     → path ends with "/X" (or equals "X")
//	"X/**"     → path starts with "X/", contains "/X/", or equals X
//	"*.ext"    → path ends with ".ext"
//	"X"        → literal match, or basename match if X has no slash
package skiplist

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func ShouldSkip(path string) bool {
	if path == "" {
		return false
	}
	path = filepath.ToSlash(path)
	for _, pat := range allPatterns() {
		if matchGlob(pat, path) {
			return true
		}
	}
	return false
}

// SkipPathsFromProject is injected by main; wired this way to avoid an
// import cycle between rules (which discovers .ctxcop.toml) and skiplist.
var SkipPathsFromProject func() []string

var defaultPatterns = []string{
	"**/testdata/**",
	"**/fixtures/**",
	"**/__fixtures__/**",
	"**/cassettes/**",
	"**/.ctxcop/**",
	"**/tests/**",
	"**/test/**",
	"**/spec/**",
	"*_test.*",
	"test_*.py",
	"*.test.*",
	"*.spec.*",
	"*.fixture.*",
	"*.golden",
	"*.snap",
}

var (
	projectOnce sync.Once
	projectPats []string
)

// ResetForTest clears the project-skip cache; production code must not call.
func ResetForTest() {
	projectOnce = sync.Once{}
	projectPats = nil
}

func allPatterns() []string {
	out := make([]string, 0, len(defaultPatterns)+8)
	out = append(out, defaultPatterns...)
	if env := os.Getenv("CTXCOP_SKIP_PATHS"); env != "" {
		for _, p := range strings.Split(env, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	projectOnce.Do(loadProject)
	out = append(out, projectPats...)
	return out
}

func loadProject() {
	if SkipPathsFromProject != nil {
		projectPats = SkipPathsFromProject()
	}
}

func matchGlob(pat, path string) bool {
	pat = filepath.ToSlash(pat)

	hasPrefixStars := strings.HasPrefix(pat, "**/")
	hasSuffixStars := strings.HasSuffix(pat, "/**")

	switch {
	case hasPrefixStars && hasSuffixStars:
		mid := strings.TrimSuffix(strings.TrimPrefix(pat, "**/"), "/**")
		return strings.Contains(path, "/"+mid+"/") ||
			strings.HasPrefix(path, mid+"/") ||
			strings.HasSuffix(path, "/"+mid) ||
			path == mid
	case hasPrefixStars:
		return matchGlob(strings.TrimPrefix(pat, "**/"), path) ||
			strings.HasSuffix(path, "/"+strings.TrimPrefix(pat, "**/"))
	case hasSuffixStars:
		// Permissive: "X/**" matches anywhere named X, not anchored at repo root.
		prefix := strings.TrimSuffix(pat, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix ||
			strings.Contains(path, "/"+prefix+"/") ||
			strings.HasSuffix(path, "/"+prefix)
	}

	if ok, _ := filepath.Match(pat, path); ok {
		return true
	}
	if ok, _ := filepath.Match(pat, filepath.Base(path)); ok {
		return true
	}
	return false
}
