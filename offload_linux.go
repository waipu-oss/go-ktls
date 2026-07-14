package ktls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// setsockopt option names and cmsg types on SOL_TLS, from include/uapi/linux/tls.h
// (not yet exposed by golang.org/x/sys/unix).
const (
	tlsTX            = 1 // TLS_TX
	tlsRX            = 2 // TLS_RX
	tlsTXZerocopyRO  = 3 // TLS_TX_ZEROCOPY_RO (kernel >= 5.19)
	tlsRXExpectNoPad = 4 // TLS_RX_EXPECT_NO_PAD
	tlsSetRecordType = 1 // TLS_SET_RECORD_TYPE
	tlsGetRecordType = 2 // TLS_GET_RECORD_TYPE
)

// errConnUnusable means kTLS TX was already installed when a later setup step
// failed; the connection cannot fall back to userspace TLS and must be closed.
var errConnUnusable = errors.New("ktls: connection unusable after partial offload")

// kernelSupport probes the "tls" ULP once on a throwaway socket; Available
// exposes the result.
var kernelSupport = sync.OnceValue(func() bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)

	// The probe socket is not connected. A kernel with kTLS support reports
	// ENOTCONN here (the "tls" ULP is recognized but its init requires an
	// established connection) whereas a kernel without the tls module reports
	// ENOENT. (Setting TCP_ULP also triggers autoloading of the module.) So
	// both success and ENOTCONN mean kTLS is available; only ENOTCONN occurs
	// in practice on a modern kernel from an unconnected socket.
	err = unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_ULP, "tls")
	return err == nil || errors.Is(err, unix.ENOTCONN)
})

// Available reports whether the kernel supports kTLS, i.e. whether the tls
// module is loaded (see modprobe tls). It is probed once and cached. When it
// reports false, every connection falls back to userspace TLS
// (ReasonKernel).
func Available() bool {
	return kernelSupport()
}

// offload installs kTLS on the raw connection using the prepared crypto_info
// blobs. The kernel picks TLS_HW (NIC inline crypto) over TLS_SW on its own
// when the device supports the session: on mainline Linux that is TLS 1.2
// AES-GCM only.
//
// Errors wrapping errConnUnusable mean the socket is half-offloaded and must
// be closed; other errors permit a clean fallback to userspace TLS.
func offload(raw net.Conn, state tls.ConnectionState, keys offloadKeys) (net.Conn, error) {
	sc, ok := raw.(syscall.Conn)
	if !ok {
		return nil, errors.New("ktls: connection does not expose a file descriptor")
	}

	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}

	if err := controlFD(rc, func(fd int) error {
		return unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_ULP, "tls")
	}); err != nil {
		// ULP without crypto_info leaves the socket as passthrough TCP, so
		// userspace TLS still works.
		return nil, fmt.Errorf("ktls: TCP_ULP: %w", err)
	}

	if err := setTLSCrypto(rc, tlsTX, keys.tx); err != nil {
		return nil, fmt.Errorf("ktls: TLS_TX: %w", err)
	}

	enableTXZerocopy(rc)

	// From here on the send path is offloaded and there is no way back.
	if err := setTLSCrypto(rc, tlsRX, keys.rx); err != nil {
		return nil, fmt.Errorf("%w: TLS_RX: %w", errConnUnusable, err)
	}

	if state.Version == tls.VersionTLS13 {
		enableRXNoPad(rc)
	}

	// keys.rxSecret/txSecret are uniquely owned (hex-decoded fresh in the key
	// log sniffer), so no defensive copy is needed.
	return &conn{Conn: raw, rc: rc, state: state, rxSecret: keys.rxSecret, txSecret: keys.txSecret}, nil
}

// controlFD runs fn on the connection's file descriptor inside
// syscall.RawConn.Control, which pins the fd for the duration of the call.
// Holding a bare fd integer instead would race with a concurrent Close: the
// kernel can reassign the freed fd number to an unrelated socket (e.g. a
// freshly accepted connection) and the syscall would target that socket.
func controlFD(rc syscall.RawConn, fn func(fd int) error) error {
	var opErr error
	if err := rc.Control(func(fd uintptr) { opErr = fn(int(fd)) }); err != nil {
		return err
	}

	return opErr
}

// setTLSCrypto installs a crypto_info struct on the SOL_TLS level.
func setTLSCrypto(rc syscall.RawConn, direction int, info []byte) error {
	return controlFD(rc, func(fd int) error {
		return unix.SetsockoptString(fd, unix.SOL_TLS, direction, string(info))
	})
}

// enableTXZerocopy requests the TX zero-copy sendfile mode (TLS_TX_ZEROCOPY_RO).
// The flag only has an effect when the kernel chose device offload (TLS_HW,
// i.e. TLS 1.2 AES-GCM on a capable NIC): it keeps MSG_SPLICE_PAGES on the
// device send path so the NIC encrypts straight from the page cache
// (net/tls/tls_device.c). The software path (all TLS 1.3 sessions) ignores it;
// there sendfile is already plaintext-copy-free, since MSG_SPLICE_PAGES
// hands the page-cache pages directly to the AEAD as its source
// (tls_sw_sendmsg_splice).
//
// Zero-copy-RO requires that the pages are not modified while in flight, which
// holds for the immutable files a static/cached response is served from. Best-
// effort: failure keeps the copying device send path; the offload itself is
// unaffected.
func enableTXZerocopy(rc syscall.RawConn) {
	_ = controlFD(rc, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_TLS, tlsTXZerocopyRO, 1)
	})
}

// enableRXNoPad declares that we do not expect padded TLS 1.3 records
// (TLS_RX_EXPECT_NO_PAD), letting the kernel decrypt records directly into
// the user buffer instead of staging them in a kernel buffer first. Real
// clients (crypto/tls, browsers, players) do not pad; if one ever does, the
// kernel transparently retries without zero-copy (counted in
// TlsRxNoPadViolation/TlsDecryptRetry), so correctness is unaffected.
// TLS 1.3 only: the kernel rejects it for other versions. Best-effort.
func enableRXNoPad(rc syscall.RawConn) {
	_ = controlFD(rc, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_TLS, tlsRXExpectNoPad, 1)
	})
}

// updateKey re-arms one direction of the kernel TLS state with the next
// traffic secret after a KeyUpdate (supported on the kernel >= 6.14
// baseline). direction is tlsRX (peer-initiated KeyUpdate) or tlsTX (our
// reciprocal KeyUpdate; must be called after the announcing record went out,
// see sendKeyUpdate). TLS_RX_EXPECT_NO_PAD survives the key switch (it is
// socket state (ctx->rx_no_pad), not key state) so it is not re-armed here.
func updateKey(rc syscall.RawConn, direction int, secret []byte, cipherSuiteID uint16) error {
	info, err := buildCryptoInfo(secret, cipherSuiteID, 0) // rec_seq restarts at 0 after a key update
	if err != nil {
		return err
	}

	name := "TLS_RX"
	if direction == tlsTX {
		name = "TLS_TX"
	}

	if err := setTLSCrypto(rc, direction, info); err != nil {
		return fmt.Errorf("ktls: %s rekey: %w", name, err)
	}

	return nil
}

// isEKEYEXPIRED reports whether a read failed because the kernel detected a
// TLS 1.3 KeyUpdate from the peer and paused decryption.
func isEKEYEXPIRED(err error) bool {
	return errors.Is(err, unix.EKEYEXPIRED)
}

// OffloadErrno returns the symbolic errno (e.g. "EBUSY") from a failed offload
// error, or "" when it carries no syscall errno, used to label why the kernel
// rejected a kTLS install (ReasonSetsockopt / ReasonConnUnusable).
func OffloadErrno(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno == 0 {
		return ""
	}
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}

	return "errno-" + strconv.Itoa(int(errno))
}

// ctrlOOB builds the TLS_SET_RECORD_TYPE control message that makes the
// kernel emit the next sendmsg payload as a record of the given content type,
// encrypted under the current TX key.
func ctrlOOB(recordType byte) []byte {
	oob := make([]byte, unix.CmsgSpace(1))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.SOL_TLS
	hdr.Type = tlsSetRecordType
	hdr.SetLen(unix.CmsgLen(1))
	oob[unix.CmsgLen(0)] = recordType

	return oob
}

// sendCloseNotify emits a TLS close_notify alert so peers see a clean TLS
// shutdown. Alert payload: level warning(1), description close_notify(0).
//
// Single-shot on purpose: the socket is non-blocking, and with a full send
// buffer (a stalled client) sendmsg fails with EAGAIN. Close must stay
// prompt, so the alert is skipped rather than retried; the callers treat it
// as best effort.
func sendCloseNotify(rc syscall.RawConn) error {
	return controlFD(rc, func(fd int) error {
		return unix.Sendmsg(fd, []byte{1, alertCloseNotify}, ctrlOOB(recordTypeAlert), nil, 0)
	})
}

// sendKeyUpdate emits a KeyUpdate(update_not_requested) handshake record,
// encrypted under the current TX key, announcing that our subsequent records
// switch to the next TX traffic secret (see updateKey).
//
// Unlike close_notify this must not be dropped (a failure tears down the
// connection) so EAGAIN from a momentarily full send buffer (common with
// slow streaming clients) retries via RawConn.Write, which waits for
// writability on the netpoller and respects the write deadline.
func sendKeyUpdate(rc syscall.RawConn) error {
	payload := []byte{handshakeTypeKeyUpdate, 0, 0, 1, keyUpdateNotRequested}
	oob := ctrlOOB(recordTypeHandshake)

	var opErr error
	if err := rc.Write(func(fd uintptr) bool {
		opErr = unix.Sendmsg(int(fd), payload, oob, nil, 0)

		return opErr != unix.EAGAIN && opErr != unix.EINTR
	}); err != nil {
		return err
	}

	return opErr
}
