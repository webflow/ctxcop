package opencode

import "io"

// passthrough returns "{}\n" — the bridge maps that to "no opinion".
func passthrough(w io.Writer) error {
	_, _ = io.WriteString(w, "{}\n")
	return nil
}
