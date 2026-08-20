//go:build !unix

package securetemp

import "io/fs"

// Windows has no uid to compare; the Lstat symlink check in Parent still
// applies, and per-user temp dirs make the shared-tmp attack far weaker.
func checkOwner(string, fs.FileInfo) error { return nil }
