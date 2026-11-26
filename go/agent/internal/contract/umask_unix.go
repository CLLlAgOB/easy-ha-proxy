//go:build unix

package contract

import "syscall"

func setUmask(mask int) int { return syscall.Umask(mask) }
