//go:build !linux

package unixrpc

import (
	"net"
	"os"
)

// PeerUID falls back to the current process UID on non-Linux hosts.
func PeerUID(_ net.Conn) (int, error) {
	return os.Getuid(), nil
}
