//go:build !unix

package alertd

import "os"

func lockFileShared(_ *os.File) error { return nil }
func unlockFile(_ *os.File)           {}
