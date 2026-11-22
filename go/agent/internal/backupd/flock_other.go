//go:build !unix

package backupd

import "os"

func tryLockOperation(_ string) (*os.File, error) { return nil, nil }
func unlockOperation(_ *os.File)                {}
