package ktls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// maxConsecutiveControl bounds back-to-back control events (handshake
// records, alerts processed without returning, RX rekeys) without forward
// progress, so a misbehaving peer cannot spin us with a KeyUpdate flood. A
// single peer KeyUpdate costs two events (the handshake record plus the
// EKEYEXPIRED-triggered rekey).
const maxConsecutiveControl = 16

// maxControlBuf bounds the reassembly buffer for control records. The only
// legal post-handshake messages from our peers are KeyUpdates (5 bytes) and
// alerts (2 bytes); anything larger is a protocol violation.
const maxControlBuf = 64

// keyUpdateSupported gates peer-initiated TLS 1.3 rekeying. Disabled for now:
// each peer KeyUpdate costs two HKDF derivations plus sendmsg/setsockopt
// syscalls, and maxConsecutiveControl is per Read call, so a peer interleaving
// one KeyUpdate before every small application record never trips it, a
// cheap, sustained CPU amplification vector. Clients in the wild virtually
// never send KeyUpdate mid-session (see doc.go), so the connection is
// terminated instead and the client recovers with a fresh handshake. The
// rekey machinery (rekeyRX/rekeyTX) stays in place; flip this only together
// with a per-connection rekey budget that an interleaving peer cannot reset.
const keyUpdateSupported = false

// errKeyUpdateDisabled terminates connections whose peer initiates a rekey
// while keyUpdateSupported is false.
var errKeyUpdateDisabled = errors.New("ktls: peer-initiated TLS key update not supported")

// copyBufPool backs the non-zero-copy ReadFrom fallback, mirroring net/http's
// pooled copy buffers so per-response allocations stay off the hot path.
var copyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// conn is a kTLS-offloaded connection: reads and writes on the embedded raw
// TCP connection go through the kernel TLS layer.
type conn struct {
	net.Conn // the raw *net.TCPConn with kTLS active

	// rc pins the socket fd for recvmsg/setsockopt/sendmsg syscalls; see
	// controlFD.
	rc    syscall.RawConn
	state tls.ConnectionState

	// rxSecret/txSecret are the current TLS 1.3 application traffic secrets,
	// advanced on key updates; nil for TLS 1.2 (no KeyUpdate). rxSecret is
	// guarded by the usual net.Conn contract of at most one concurrent Read;
	// txSecret by wmu.
	rxSecret []byte
	txSecret []byte

	// Read-side scratch, single-reader by the net.Conn contract: oob receives
	// the kernel's TLS_GET_RECORD_TYPE cmsg; ctrl reassembles control-record
	// payloads (alerts, post-handshake messages) that may arrive fragmented.
	oob      [24]byte // >= unix.CmsgSpace(1)
	ctrl     []byte
	ctrlType byte

	// recvFn is rc.Read's callback, bound once per conn so a recvmsg does not
	// heap-allocate a fresh closure on every Read. rxBuf carries the per-call
	// destination buffer; rxN/rxType/rxErr its result. Single-reader by the
	// net.Conn contract, like oob/ctrl above.
	recvFn func(uintptr) bool
	rxBuf  []byte
	rxN    int
	rxType byte
	rxErr  error

	// wmu serializes the send path with TX rekeys: a reciprocal KeyUpdate is
	// two userspace steps (send the KeyUpdate record, then switch the kernel
	// TX key), and a record written in between would go out under the old key
	// after the peer was told to switch. Held across whole ReadFrom transfers,
	// which also satisfies RFC 8446 section 4.6.3 (our KeyUpdate must precede
	// our next application data, not interrupt in-flight data).
	wmu sync.Mutex

	closeNotifyOnce sync.Once
	closeOnce       sync.Once
	closeErr        error
}

// Read receives decrypted application data through the kernel TLS layer.
//
// It uses recvmsg with a control-message buffer rather than plain read(2):
// the kernel reports each record's TLS content type via a TLS_GET_RECORD_TYPE
// cmsg and fails non-application-data records with EIO when no cmsg buffer is
// supplied; a plain read would turn a peer's clean close_notify into an I/O
// error and make post-handshake messages unreadable. Alerts and KeyUpdates
// are handled here: close_notify maps to io.EOF; a peer KeyUpdate terminates
// the connection while keyUpdateSupported is false (when enabled, it re-arms
// the kernel RX path with the next traffic secret and answers with our own
// KeyUpdate when the peer requested it).
//
// Errors come from the raw socket layer (e.g. os.ErrDeadlineExceeded on read
// deadlines) rather than wrapped in *net.OpError.
func (c *conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	for events := 0; ; events++ {
		if events >= maxConsecutiveControl {
			return 0, errors.New("ktls: too many consecutive TLS control events")
		}

		n, recType, err := c.recvRecord(b)
		if err != nil {
			// EKEYEXPIRED: the kernel paused RX after a peer KeyUpdate
			// (kernel >= 6.14) until we provide the next RX key.
			if c.rxSecret != nil && isEKEYEXPIRED(err) {
				if !keyUpdateSupported {
					return 0, errKeyUpdateDisabled
				}
				if rerr := c.rekeyRX(); rerr != nil {
					return 0, rerr
				}

				continue
			}

			return n, err
		}

		switch recType {
		case recordTypeApplicationData:
			if n == 0 {
				continue // zero-length record, keep waiting for data
			}

			return n, nil
		case recordTypeAlert, recordTypeHandshake:
			eof, herr := c.handleControl(recType, b[:n])
			if herr != nil {
				return 0, herr
			}
			if eof {
				return 0, io.EOF
			}
		default:
			return 0, fmt.Errorf("ktls: unexpected TLS record type %d", recType)
		}
	}
}

// doRecvmsg is c.recvFn: it reads one record into rxBuf and stores the result
// in rxN/rxType/rxErr, returning false so the netpoller retries on EAGAIN/EINTR.
func (c *conn) doRecvmsg(fd uintptr) bool {
	c.rxN, c.rxType, c.rxErr = recvmsgRecordType(int(fd), c.rxBuf, c.oob[:])

	return !errors.Is(c.rxErr, unix.EAGAIN) && !errors.Is(c.rxErr, unix.EINTR)
}

// recvRecord performs one recvmsg on the kTLS socket and returns the data
// read plus the record content type from the kernel's cmsg (application data
// when the kernel attached none). A zero-byte result without a cmsg is the
// TCP FIN, reported as io.EOF.
func (c *conn) recvRecord(b []byte) (n int, recType byte, err error) {
	if c.recvFn == nil {
		c.recvFn = c.doRecvmsg
	}
	c.rxBuf = b

	if err := c.rc.Read(c.recvFn); err != nil {
		return 0, 0, err // deadline exceeded or connection closed
	}
	if c.rxErr != nil {
		return 0, 0, c.rxErr
	}

	n, recType = c.rxN, c.rxType
	if n == 0 && recType == 0 {
		return 0, 0, io.EOF
	}
	if recType == 0 {
		recType = recordTypeApplicationData
	}

	return n, recType, nil
}

// recvmsgRecordType wraps unix.Recvmsg and extracts the TLS_GET_RECORD_TYPE
// control message, returning recType 0 when the kernel attached none. The
// cmsg layout mirrors the one ctrlOOB constructs.
func recvmsgRecordType(fd int, b, oob []byte) (n int, recType byte, err error) {
	n, oobn, recvflags, _, err := unix.Recvmsg(fd, b, oob, 0)
	if err != nil {
		return n, 0, err
	}

	// A truncated control buffer (MSG_CTRUNC) means the record-type cmsg is
	// unreliable: falling through to recType 0 would mis-deliver an alert or
	// handshake record as plaintext application data. Fail the read instead.
	// The oob buffer fits exactly the one cmsg the kernel attaches, so this
	// only triggers if an unexpected extra cmsg appears (e.g. socket
	// timestamping enabled out of band).
	if recvflags&unix.MSG_CTRUNC != 0 {
		return n, 0, errors.New("ktls: truncated TLS control message (MSG_CTRUNC)")
	}
	if oobn < unix.CmsgLen(1) {
		return n, 0, nil
	}

	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	if hdr.Level == unix.SOL_TLS && hdr.Type == tlsGetRecordType {
		recType = oob[unix.CmsgLen(0)]
	}

	return n, recType, nil
}

// handleControl reassembles and processes an alert or post-handshake record
// payload. It reports eof for a peer close_notify; KeyUpdates trigger a
// reciprocal TX rekey when requested (the RX side rekeys via the
// EKEYEXPIRED on the following read).
func (c *conn) handleControl(recType byte, data []byte) (eof bool, err error) {
	if len(c.ctrl) > 0 && c.ctrlType != recType {
		return false, errors.New("ktls: interleaved fragmented TLS control records")
	}

	c.ctrlType = recType
	// Bound the buffer before appending: data is a whole record body (up to
	// ~16 KiB), so checking post-append would copy it only to discard it.
	if len(c.ctrl)+len(data) > maxControlBuf {
		return false, errors.New("ktls: oversized TLS control message")
	}
	c.ctrl = append(c.ctrl, data...)

	switch recType {
	case recordTypeAlert:
		// Alerts are two bytes each; a record may carry several (e.g.
		// user_canceled followed by close_notify). Fewer than two buffered
		// bytes means a fragment: wait for the rest.
		for len(c.ctrl) >= 2 {
			closeNotify, aerr := parseAlert(c.ctrl[0], c.ctrl[1])
			if closeNotify || aerr != nil {
				c.ctrl = c.ctrl[:0]

				return closeNotify, aerr
			}

			// Ignored warning-level alert (user_canceled): keep scanning.
			c.ctrl = append(c.ctrl[:0], c.ctrl[2:]...)
		}

		return false, nil

	default: // recordTypeHandshake
		if !keyUpdateSupported {
			// The only legal post-handshake message from a client is
			// KeyUpdate, and rekeying is disabled: reject before doing any
			// parse or crypto work.
			return false, errKeyUpdateDisabled
		}

		rest, txRekey, herr := parseKeyUpdates(c.ctrl)
		if herr != nil {
			c.ctrl = c.ctrl[:0] // don't let a later read misreport the stale fragment

			return false, herr
		}
		c.ctrl = append(c.ctrl[:0], rest...)

		if txRekey {
			if rerr := c.rekeyTX(); rerr != nil {
				return false, rerr
			}
		}

		return false, nil
	}
}

// rekeyRX re-arms the kernel RX path with the next application traffic
// secret after the kernel paused decryption on a peer KeyUpdate.
func (c *conn) rekeyRX() error {
	next, err := deriveNextSecret(c.rxSecret, c.state.CipherSuite)
	if err != nil {
		return err
	}

	if err := updateKey(c.rc, tlsRX, next, c.state.CipherSuite); err != nil {
		return err
	}

	c.rxSecret = next

	return nil
}

// rekeyTX answers a peer's update_requested KeyUpdate (RFC 8446 section
// 4.6.3): send our own KeyUpdate record under the current TX key, then switch
// the kernel to the next TX traffic secret. wmu keeps concurrent writes from
// slipping between the two steps. On kernels < 6.14 the TX key switch fails
// with EBUSY; the resulting error closes the connection (which a pre-rekey
// kernel cannot keep alive anyway).
func (c *conn) rekeyTX() error {
	if c.txSecret == nil {
		return errors.New("ktls: peer requested a key update on a non-rekeyable connection")
	}

	next, err := deriveNextSecret(c.txSecret, c.state.CipherSuite)
	if err != nil {
		return err
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	if err := sendKeyUpdate(c.rc); err != nil {
		return fmt.Errorf("ktls: send KeyUpdate: %w", err)
	}

	if err := updateKey(c.rc, tlsTX, next, c.state.CipherSuite); err != nil {
		// The KeyUpdate announcing the switch is out but the kernel still
		// holds the old key (e.g. EBUSY on kernels < 6.14): anything sent
		// from here on would fail to decrypt at the peer. Suppress the
		// close_notify so teardown doesn't emit a record under the stale key.
		c.closeNotifyOnce.Do(func() {})

		return err
	}

	c.txSecret = next

	return nil
}

// Write serializes with TX rekeys (see wmu).
func (c *conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	return c.Conn.Write(b)
}

// ReadFrom lets io.Copy and net/http push data through the kernel TLS layer.
// Zero-copy-eligible sources (files, TCP/Unix conns) are delegated to the
// underlying *net.TCPConn for sendfile(2)/splice(2); everything else is
// copied with a pooled buffer; delegating those too would land in
// net.genericReadFrom, which allocates a fresh 32 KiB buffer per call.
func (c *conn) ReadFrom(r io.Reader) (int64, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if rf, ok := c.Conn.(io.ReaderFrom); ok && zeroCopyEligible(r) {
		return rf.ReadFrom(r)
	}

	buf := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(buf)

	return io.CopyBuffer(writerOnly{c}, r, *buf)
}

// writerOnly hides ReadFrom from io.CopyBuffer and writes to the underlying
// connection directly: ReadFrom already holds wmu, so routing through c.Write
// (or back into c.ReadFrom) would deadlock.
type writerOnly struct{ c *conn }

func (w writerOnly) Write(b []byte) (int, error) {
	return w.c.Conn.Write(b)
}

// zeroCopyEligible mirrors the source types *net.TCPConn.ReadFrom can splice
// or sendfile from without falling back to an allocating generic copy.
func zeroCopyEligible(r io.Reader) bool {
	if lr, ok := r.(*io.LimitedReader); ok {
		r = lr.R
	}

	switch r.(type) {
	case *os.File, *net.TCPConn, *net.UnixConn:
		return true
	default:
		return false
	}
}

// Close sends a close_notify alert (best effort) before closing the socket so
// peers see a clean TLS shutdown rather than a truncation. It intentionally
// does not take wmu: Close must be able to interrupt a stuck ReadFrom
// transfer, so the (rare, harmless-at-teardown) race with an in-flight TX
// rekey is accepted.
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.sendCloseNotify()
		c.closeErr = c.Conn.Close()
	})

	return c.closeErr
}

// CloseWrite implements the closeWriter interface net/http uses for graceful
// shutdown of the write side.
func (c *conn) CloseWrite() error {
	cw, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}

	c.sendCloseNotify()

	return cw.CloseWrite()
}

// sendCloseNotify emits the close_notify alert at most once per connection:
// net/http calls CloseWrite followed by Close, which must not produce a
// second alert.
func (c *conn) sendCloseNotify() {
	c.closeNotifyOnce.Do(func() { _ = sendCloseNotify(c.rc) })
}

// SyscallConn exposes the raw fd, e.g. for zero-copy splicing by callers.
func (c *conn) SyscallConn() (syscall.RawConn, error) {
	return c.rc, nil
}

// ConnectionState lets net/http populate Request.TLS.
func (c *conn) ConnectionState() tls.ConnectionState {
	return c.state
}

// NetConn returns the underlying raw connection, mirroring
// (*tls.Conn).NetConn so callers can unwrap to the *net.TCPConn
// (e.g. for TCP_INFO collection).
func (c *conn) NetConn() net.Conn {
	return c.Conn
}

var _ Conn = (*conn)(nil)
