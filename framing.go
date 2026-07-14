package ktls

import (
	"net"
)

const recordHeaderLen = 5

// TLS record content types we care about.
const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

// framedConn wraps the raw TCP connection for the duration of the userspace
// handshake. It enforces two invariants that make kTLS setup race-free:
//
// Read side: a single Read never returns bytes past the current TLS record
// boundary, and we never request more from the socket than the current record
// has left. crypto/tls therefore consumes exactly the records it processes
// (through the client Finished) and any half-RTT application data the client
// sent early stays in the kernel receive queue, where kTLS RX picks it up.
// This means the RX record sequence number is 0 by construction and there is
// never decrypted-but-unread or partially buffered ciphertext to drain.
//
// Write side: a copy of the last complete application-data record written is
// retained. crypto/tls buffers its handshake flight, so write ordering cannot
// tell handshake-key records from application-key records (both are disguised
// as application data); instead the listener trial-decrypts this last record
// with the application traffic key to determine the TX sequence number the
// kernel has to continue with (see computeTXSeq).
//
// framedConn is used by a single goroutine (the handshake) and must be
// release()d (fallback) or bypassed (offload wraps the raw conn) afterwards.
type framedConn struct {
	net.Conn

	released bool

	// read side state
	rHdr     [recordHeaderLen]byte
	rHdrN    int
	rBodyRem int
	rxApp    int

	// TLS 1.2 ClientHello capture, mirroring the outbound ServerHello capture
	// below: on a resumed handshake the key log carries no client random, so it
	// is taken from the first inbound handshake record. Runs for every
	// connection (version unknown at read time) and must not allocate.
	rHello     [clientHelloPrefixLen]byte
	rHelloN    int
	rHelloSeen bool

	// write side state
	wHdr     [recordHeaderLen]byte
	wHdrN    int
	wBodyRem int
	wCur     []byte // application-data record currently being written
	wLast    []byte // last complete application-data record written

	// TLS 1.2 ServerHello capture: the NSS key log only carries the client
	// random, but the key expansion (RFC 5246 section 6.3) also needs the
	// server random, which we send ourselves, in plaintext, as the first
	// outgoing handshake record. Capture its prefix through the random into a
	// fixed array (the version is unknown at write time, so this runs for
	// every connection and must not allocate).
	wHello     [serverHelloPrefixLen]byte
	wHelloN    int
	wHelloSeen bool

	// TLS 1.2 server Finished capture: the first handshake record written
	// after our outgoing ChangeCipherSpec is the encrypted Finished, which
	// the listener trial-decrypts to confirm the derived keys (see
	// verifyServerFinished). Captured into a small bounded buffer.
	wCCSSeen     bool
	wFinished    []byte
	wFinishedCap bool
}

// serverHelloPrefixLen covers HandshakeType(1) + length(3) + legacy_version(2) + random(32).
const serverHelloPrefixLen = 38

// clientHelloPrefixLen has the same layout as the ServerHello prefix
// (HandshakeType(1) + length(3) + legacy_version(2) + random(32)).
const clientHelloPrefixLen = serverHelloPrefixLen

// maxFinishedBody bounds the captured Finished record body (explicit nonce +
// verify_data ciphertext + tag is well under this for AES-GCM).
const maxFinishedBody = 256

// release turns the connection into a passthrough wrapper. Used on the
// userspace-TLS fallback path to avoid capped reads for the rest of the
// connection's lifetime.
func (f *framedConn) release() {
	f.released = true
}

// NetConn returns the underlying raw connection. On the fallback path the
// *tls.Conn returned from Accept wraps a framedConn, so callers unwrapping
// via NetConn (e.g. for TCP_INFO collection) reach the *net.TCPConn.
func (f *framedConn) NetConn() net.Conn {
	return f.Conn
}

// readAtBoundary reports whether the read side sits exactly on a TLS record
// boundary, i.e. no header or body bytes of a further record were consumed.
func (f *framedConn) readAtBoundary() bool {
	return f.rHdrN == 0 && f.rBodyRem == 0
}

func (f *framedConn) Read(b []byte) (int, error) {
	if f.released {
		return f.Conn.Read(b)
	}

	// Cap the read at the next sub-boundary (end of header or end of body)
	// so we never pull bytes of a following record out of the kernel.
	need := f.rBodyRem
	if need == 0 {
		need = recordHeaderLen - f.rHdrN
	}
	if len(b) > need {
		b = b[:need]
	}

	n, err := f.Conn.Read(b)
	f.consumeRead(b[:n])

	return n, err
}

func (f *framedConn) consumeRead(data []byte) {
	for len(data) > 0 {
		if f.rBodyRem > 0 {
			n := min(len(data), f.rBodyRem)
			// Capture the ClientHello prefix. Re-check the record type rather
			// than trust the latched rHelloSeen: a client could interleave a
			// non-handshake record into the capture window. Concatenating only
			// handshake-record bodies still reassembles a fragmented message.
			if f.rHelloSeen && f.rHdr[0] == recordTypeHandshake && f.rHelloN < clientHelloPrefixLen {
				f.rHelloN += copy(f.rHello[f.rHelloN:], data[:n])
			}
			f.rBodyRem -= n
			data = data[n:]
			if f.rBodyRem == 0 && f.rHdr[0] == recordTypeApplicationData {
				f.rxApp++
			}

			continue
		}

		n := copy(f.rHdr[f.rHdrN:], data)
		f.rHdrN += n
		data = data[n:]
		if f.rHdrN < recordHeaderLen {
			return
		}

		// Full header: type(1) + version(2) + length(2).
		f.rHdrN = 0
		f.rBodyRem = int(f.rHdr[3])<<8 | int(f.rHdr[4])
		// The first inbound handshake record carries the ClientHello.
		if f.rHdr[0] == recordTypeHandshake && !f.rHelloSeen {
			f.rHelloSeen = true
		}
		if f.rBodyRem == 0 && f.rHdr[0] == recordTypeApplicationData {
			f.rxApp++ // zero-length record; invalid in practice but keep state sane
		}
	}
}

func (f *framedConn) Write(b []byte) (int, error) {
	if !f.released {
		f.consumeWrite(b)
	}

	return f.Conn.Write(b)
}

func (f *framedConn) consumeWrite(data []byte) {
	for len(data) > 0 {
		if f.wBodyRem > 0 {
			n := min(len(data), f.wBodyRem)
			f.wBodyRem -= n
			if f.wCur != nil {
				f.wCur = append(f.wCur, data[:n]...)
			}
			if f.wHelloSeen && f.wHdr[0] == recordTypeHandshake && f.wHelloN < serverHelloPrefixLen {
				f.wHelloN += copy(f.wHello[f.wHelloN:], data[:n])
			}
			if f.wFinishedCap && len(f.wFinished) < maxFinishedBody {
				f.wFinished = append(f.wFinished, data[:min(n, maxFinishedBody-len(f.wFinished))]...)
			}
			data = data[n:]
			if f.wBodyRem == 0 {
				f.wFinishedCap = false
				if f.wCur != nil {
					f.wLast, f.wCur = f.wCur, nil
				}
			}

			continue
		}

		n := copy(f.wHdr[f.wHdrN:], data)
		f.wHdrN += n
		data = data[n:]
		if f.wHdrN < recordHeaderLen {
			return
		}

		f.wHdrN = 0
		f.wBodyRem = int(f.wHdr[3])<<8 | int(f.wHdr[4])

		switch f.wHdr[0] {
		case recordTypeApplicationData:
			f.wCur = append(make([]byte, 0, recordHeaderLen+f.wBodyRem), f.wHdr[:]...)
			if f.wBodyRem == 0 {
				f.wLast, f.wCur = f.wCur, nil
			}
		case recordTypeChangeCipherSpec:
			f.wCur = nil
			f.wCCSSeen = true
		case recordTypeHandshake:
			f.wCur = nil
			// First handshake record carries the ServerHello (server random);
			// the first one after our ChangeCipherSpec is the encrypted Finished.
			if !f.wHelloSeen {
				f.wHelloSeen = true
			} else if f.wCCSSeen && f.wFinished == nil {
				f.wFinishedCap = f.wBodyRem > 0
				f.wFinished = make([]byte, 0, min(f.wBodyRem, maxFinishedBody))
			}
		default:
			f.wCur = nil
		}
	}
}

// helloRandom returns the 32-byte random from a captured Hello prefix
// (HandshakeType(1) + length(3) + legacy_version(2) + random(32)), reporting
// false unless the full prefix was captured and the message type matches.
func helloRandom(prefix []byte, captured int, msgType byte) ([]byte, bool) {
	if captured < len(prefix) || prefix[0] != msgType {
		return nil, false
	}

	return prefix[6:38], true
}

// clientRandom returns the 32-byte client random from the captured ClientHello
// prefix, used to recover a resumed TLS 1.2 session's keys from the wire.
func (f *framedConn) clientRandom() ([]byte, bool) {
	const handshakeTypeClientHello = 1

	return helloRandom(f.rHello[:], f.rHelloN, handshakeTypeClientHello)
}

// serverRandom returns the 32-byte server random parsed from the captured
// ServerHello prefix (TLS 1.2 key expansion needs it; the key log doesn't
// carry it).
func (f *framedConn) serverRandom() ([]byte, bool) {
	const handshakeTypeServerHello = 2

	return helloRandom(f.wHello[:], f.wHelloN, handshakeTypeServerHello)
}

// serverFinished returns the captured body of the encrypted server Finished
// record (the first handshake record after our ChangeCipherSpec), used to
// verify the derived TLS 1.2 keys before offload.
func (f *framedConn) serverFinished() ([]byte, bool) {
	if f.wFinishedCap || len(f.wFinished) == 0 {
		return nil, false // never captured, or capture truncated mid-record
	}

	return f.wFinished, true
}
