//go:build !linux

package ktls

import (
	"crypto/tls"
	"errors"
	"net"
)

var errConnUnusable = errors.New("ktls: connection unusable after partial offload")

// Available reports whether the kernel supports kTLS. Always false off Linux;
// every connection falls back to userspace TLS.
func Available() bool {
	return false
}

func offload(net.Conn, tls.ConnectionState, offloadKeys) (net.Conn, error) {
	return nil, errors.ErrUnsupported
}

// OffloadErrno mirrors the Linux build; offload never runs off Linux.
func OffloadErrno(error) string { return "" }
