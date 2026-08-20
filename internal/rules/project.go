package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
)

// projectConfig pulls ctxcop-specific fields out of .ctxcop.toml before
// the file is fed to the gitleaks loader. Currently just skip_paths,
// which isn't part of the upstream rule schema.
type projectConfig struct {
	SkipPaths []string `toml:"skip_paths"`
}

var (
	projectOnce sync.Once
	projectPath string
	projectCfg  projectConfig
)

// ProjectConfigPath returns the discovered .ctxcop.toml path or "".
func ProjectConfigPath() string {
	projectOnce.Do(discoverProject)
	return projectPath
}

// ProjectSkipPaths returns the project's skip_paths, fed into skiplist
// via main's SkipPathsFromProject wiring.
func ProjectSkipPaths() []string {
	projectOnce.Do(discoverProject)
	return projectCfg.SkipPaths
}

// discoverProject walks up from cwd, bounded at 8 ancestors so a
// pathological path doesn't stat() its way to root on every hook call.
func discoverProject() {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, ".ctxcop.toml")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			projectPath = candidate
			data, err := os.ReadFile(candidate)
			if err == nil {
				if err := toml.Unmarshal(data, &projectCfg); err != nil {
					fmt.Fprintf(os.Stderr, "ctxcop: parse %s: %v (skip_paths ignored)\n", candidate, err)
				}
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}
