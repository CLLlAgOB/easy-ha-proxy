package stages

import (
	"os"
	"syscall"
)

// fileOwner is a file's uid and gid (stat's uid and gid).
func fileOwner(fi os.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}
