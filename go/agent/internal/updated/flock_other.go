//go:build !unix

package updated

import "os"

func tryLockMaintenance(_ string) (*os.File, error) { return nil, nil }
func unlockMaintenance(_ *os.File)                  {}
