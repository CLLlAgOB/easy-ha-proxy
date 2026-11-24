//go:build !linux

package unixrpc

import (
	"errors"
	"net"
)

// PeerUID is unavailable on hosts without Linux peer credentials.
func PeerUID(_ net.Conn) (int, error) {
	return -1, errors.New("Unix peer credentials are unsupported")
}
