//go:build linux

package backupd

import "syscall"

func frsizeOf(st *syscall.Statfs_t) int64 { return int64(st.Frsize) }
