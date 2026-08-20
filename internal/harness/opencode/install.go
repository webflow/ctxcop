// Package opencode is the OpenCode (sst/opencode) harness adapter.
//
// OpenCode auto-discovers plugins from ~/.config/opencode/plugins/ (user)
// or <cwd>/.opencode/plugins/ (project). See docs/harnesses.md for design.
package opencode

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed extension/ctxcop.ts
var bridgeSource string

const pluginFilename = "ctxcop.ts"

func SettingsPath(scope string) (string, error) {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".config", "opencode", "plugins", pluginFilename), nil
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".opencode", "plugins", pluginFilename), nil
	default:
		return "", fmt.Errorf("ctxcop: unknown scope %q", scope)
	}
}

func Install(scope string, w io.Writer) (string, error) {
	path, err := SettingsPath(scope)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("ctxcop: create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(bridgeSource), 0o644); err != nil {
		return "", fmt.Errorf("ctxcop: write %s: %w", path, err)
	}
	fmt.Fprintf(w, "ctxcop: wrote opencode plugin to %s\n", path)
	return path, nil
}

func Uninstall(scope string, w io.Writer) (string, int, error) {
	path, err := SettingsPath(scope)
	if err != nil {
		return "", 0, err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return path, 0, nil
		}
		return "", 0, fmt.Errorf("ctxcop: remove %s: %w", path, err)
	}
	fmt.Fprintf(w, "ctxcop: removed opencode plugin at %s\n", path)
	return path, 1, nil
}

// IsPresent probes whether opencode is installed at the given scope.
// User scope: ~/.config/opencode/ or ~/.local/share/opencode/ (Bun
// install layout); project scope: <cwd>/.opencode/ or <cwd>/opencode.json.
func IsPresent(scope string) bool {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		for _, p := range []string{
			filepath.Join(home, ".config", "opencode"),
			filepath.Join(home, ".local", "share", "opencode"),
		} {
			if _, err := os.Stat(p); err == nil {
				return true
			}
		}
		return false
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return false
		}
		for _, p := range []string{
			filepath.Join(cwd, ".opencode"),
			filepath.Join(cwd, "opencode.json"),
		} {
			if _, err := os.Stat(p); err == nil {
				return true
			}
		}
		return false
	}
	return false
}

// BridgeSource exposes the embedded ctxcop.ts content for tests.
func BridgeSource() string {
	return strings.Clone(bridgeSource)
}
