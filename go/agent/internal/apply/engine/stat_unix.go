package engine

import (
	"os"
	"syscall"
)

type ownership struct{ uid, gid int }

func statT(fi os.FileInfo) (ownership, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ownership{}, false
	}
	return ownership{int(st.Uid), int(st.Gid)}, true
}
