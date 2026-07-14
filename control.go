package ktls

import (
	"fmt"
)

// TLS alert and post-handshake message constants (RFC 8446).
const (
	alertCloseNotify  = 0
	alertUserCanceled = 90

	handshakeTypeKeyUpdate = 24

	keyUpdateNotRequested = 0
	keyUpdateRequested    = 1
)

// parseAlert interprets one two-byte alert. closeNotify reports a clean peer
// shutdown; user_canceled is the one warning-level alert RFC 8446 section 6.1
// tells us to ignore (a close_notify follows it), reported as (false, nil).
// Every other alert terminates the connection.
func parseAlert(level, desc byte) (closeNotify bool, err error) {
	switch desc {
	case alertCloseNotify:
		return true, nil
	case alertUserCanceled:
		return false, nil
	default:
		return false, fmt.Errorf("ktls: received TLS alert %d (level %d)", desc, level)
	}
}

// parseKeyUpdates consumes complete handshake messages from buf and returns
// the unconsumed remainder. The only post-handshake message we accept is
// KeyUpdate; txRekey reports whether any of them had update_requested set,
// which obliges us to answer with a KeyUpdate of our own (RFC 8446 section
// 4.6.3). Anything else (e.g. a TLS 1.2 renegotiation HelloRequest or
// post-handshake authentication) is rejected: those flows cannot be expressed
// once the record layer lives in the kernel.
func parseKeyUpdates(buf []byte) (rest []byte, txRekey bool, err error) {
	for len(buf) >= 4 {
		msgType := buf[0]
		msgLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])

		if msgType != handshakeTypeKeyUpdate {
			return nil, false, fmt.Errorf("ktls: unexpected post-handshake message type %d", msgType)
		}
		if msgLen != 1 {
			return nil, false, fmt.Errorf("ktls: malformed KeyUpdate length %d", msgLen)
		}
		if len(buf) < 4+msgLen {
			break // header complete, body still in flight
		}

		switch buf[4] {
		case keyUpdateRequested:
			txRekey = true
		case keyUpdateNotRequested:
		default:
			return nil, false, fmt.Errorf("ktls: invalid KeyUpdate request_update %d", buf[4])
		}

		buf = buf[4+msgLen:]
	}

	return buf, txRekey, nil
}
