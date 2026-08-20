// Package pi is the pi.dev harness adapter.
//
// Pi auto-discovers extensions from ~/.pi/agent/extensions/ (user) or
// <cwd>/.pi/extensions/ (project). See docs/harnesses.md for design.
package pi

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

const extensionFilename = "ctxcop.ts"

func SettingsPath(scope string) (string, error) {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".pi", "agent", "extensions", extensionFilename), nil
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".pi", "extensions", extensionFilename), nil
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
	fmt.Fprintf(w, "ctxcop: wrote pi extension to %s\n", path)
	return path, nil
}

// Uninstall returns (path, removedCount, error). Shape matches the
// other harness Uninstall functions for cmd/ctxcop dispatch parity.
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
	fmt.Fprintf(w, "ctxcop: removed pi extension at %s\n", path)
	return path, 1, nil
}

func IsPresent(scope string) bool {
	var base string
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		base = filepath.Join(home, ".pi")
	case "project":
		cwd, err := os.Getwd()
		if err != nil {
			return false
		}
		base = filepath.Join(cwd, ".pi")
	default:
		return false
	}
	_, err := os.Stat(base)
	return err == nil
}

// BridgeSource exposes the embedded ctxcop.ts content for tests.
func BridgeSource() string {
	return strings.Clone(bridgeSource)
}
