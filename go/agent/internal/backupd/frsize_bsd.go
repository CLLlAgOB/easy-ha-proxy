//go:build unix && !linux

package backupd

import "syscall"

func frsizeOf(_ *syscall.Statfs_t) int64 { return 0 }
