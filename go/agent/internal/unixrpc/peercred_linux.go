//go:build linux

// Package unixrpc provides the single-line JSON-over-AF_UNIX RPC server with
// Linux SO_PEERCRED UID verification shared by backupd and updated.
package unixrpc

import (
	"fmt"
	"net"
	"syscall"
)

// PeerUID returns the effective UID of the connected AF_UNIX peer via SO_PEERCRED.
func PeerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var uid int
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = int(ucred.Uid)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return uid, nil
}
