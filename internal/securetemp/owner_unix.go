//go:build unix

package securetemp

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkOwner rejects a parent owned by anyone but the current user.
func checkOwner(path string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("securetemp: %s is owned by uid %d, not %d", path, st.Uid, uid)
	}
	return nil
}
