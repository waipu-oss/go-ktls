package ktls

// Tests in this file exercise the offloaded connection against the real
// kernel TLS layer and are skipped when the tls module is unavailable
// (non-Linux is excluded by the build tag). They verify the control-record
// semantics that cannot be simulated in userspace: close_notify delivery as
// io.EOF and the TLS 1.3 KeyUpdate flow (kernel >= 6.14), including the
// reciprocal TX rekey for update_requested.

import (
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// reasonRecorder collects the observer reasons of a listener, so a test that
// required an offload can report why the connection fell back instead of only
// that it did.
type reasonRecorder struct {
	mu      sync.Mutex
	reasons []string
}

func (r *reasonRecorder) observe(reason string, _ net.Addr, _ tls.ConnectionState, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err != nil {
		reason = fmt.Sprintf("%s (%v)", reason, err)
	}
	r.reasons = append(r.reasons, reason)
}

func (r *reasonRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.reasons) == 0 {
		return "none"
	}

	return strings.Join(r.reasons, "; ")
}

// offloadedListener pairs a test listener with the recorder acceptOffloaded
// reads its diagnostics from.
func offloadedListener(t *testing.T, cfg *tls.Config) (*Listener, *reasonRecorder) {
	t.Helper()

	rec := &reasonRecorder{}

	return newTestListener(t, cfg, WithObserver(rec.observe)), rec
}

func requireKernelTLS(t *testing.T) {
	t.Helper()

	if !Available() {
		t.Skip("kernel TLS unavailable (tls module not loaded)")
	}
}

// acceptOffloaded accepts one connection and requires it to be kTLS-offloaded,
// naming the observer's fallback reason if it is not.
func acceptOffloaded(t *testing.T, l *Listener, rec *reasonRecorder) *conn {
	t.Helper()

	type result struct {
		c   net.Conn
		err error
	}

	ch := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		ch <- result{c, err}
	}()

	select {
	case r := <-ch:
		require.NoError(t, r.err)
		t.Cleanup(func() { _ = r.c.Close() })

		kc, ok := r.c.(*conn)
		require.True(t, ok, "expected an offloaded connection, got %T; observer reasons: %s", r.c, rec)

		return kc
	case <-time.After(10 * time.Second):
		t.Fatal("no connection accepted within 10s")

		return nil
	}
}

func TestKernelCloseNotifyMapsToEOF(t *testing.T) {
	requireKernelTLS(t)

	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}, MinVersion: tls.VersionTLS13}
	l, rec := offloadedListener(t, cfg)

	client, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		MinVersion:         tls.VersionTLS13,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Handshake())

	sc := acceptOffloaded(t, l, rec)
	require.NoError(t, sc.SetReadDeadline(time.Now().Add(10*time.Second)))

	_, err = client.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, err := sc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))

	// CloseWrite sends the client's close_notify alert; the offloaded Read
	// must surface it as a clean io.EOF, not as EIO.
	require.NoError(t, client.CloseWrite())

	n, err = sc.Read(buf)
	require.ErrorIs(t, err, io.EOF)
	assert.Zero(t, n)
}

func TestKernelPeerKeyUpdate(t *testing.T) {
	requireKernelTLS(t)

	if !keyUpdateSupported {
		// keyUpdateSupported=false posture: a peer-initiated KeyUpdate
		// terminates the connection instead of driving the rekey machinery
		// (see the constant's comment in conn_linux.go).
		k := newKeyUpdateConn(t)
		k.sendKeyUpdate(t, keyUpdateRequested)

		_, err := k.sc.Read(make([]byte, 16))
		require.ErrorIs(t, err, errKeyUpdateDisabled)

		return
	}

	for _, tc := range []struct {
		name          string
		requestUpdate byte
	}{
		{"not-requested", keyUpdateNotRequested},
		{"requested", keyUpdateRequested},
	} {
		t.Run(tc.name, func(t *testing.T) { testKernelPeerKeyUpdate(t, tc.requestUpdate) })
	}
}

// keyUpdateConn is an offloaded TLS 1.3 connection whose client side is a
// manual record layer: handshake via crypto/tls, then raw records sealed with
// the captured traffic secrets, so the client can send KeyUpdates (which
// crypto/tls cannot). One application record has already been exchanged under
// the initial keys.
type keyUpdateConn struct {
	raw    net.Conn
	sc     *conn
	tx, rx *recordCipher
}

func newKeyUpdateConn(t *testing.T) *keyUpdateConn {
	t.Helper()

	cfg := &tls.Config{
		Certificates: []tls.Certificate{testCert(t)},
		MinVersion:   tls.VersionTLS13,
		// No session tickets: the kernel TX sequence then starts at 0, so the
		// client-side record cipher for the server direction starts at 0 too.
		SessionTicketsDisabled: true,
	}
	l, rec := offloadedListener(t, cfg)

	raw, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))

	keyLog := &syncBuffer{}
	tlsClient := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		MinVersion:         tls.VersionTLS13,
		KeyLogWriter:       keyLog,
	})
	require.NoError(t, tlsClient.Handshake())
	suite := tlsClient.ConnectionState().CipherSuite
	// From here on the raw connection is driven directly; tlsClient holds no
	// buffered post-handshake bytes (the server sends nothing after its
	// Finished until written to below).

	clientSecret, err := parseTrafficSecret(keyLog.String(), labelClientTraffic)
	require.NoError(t, err)
	serverSecret, err := parseTrafficSecret(keyLog.String(), labelServerTraffic)
	require.NoError(t, err)

	sc := acceptOffloaded(t, l, rec)
	require.NoError(t, sc.SetReadDeadline(time.Now().Add(10*time.Second)))

	// With session tickets disabled nothing went out under the application
	// keys during the handshake, so both kernel sequences must start at 0.
	assert.Equal(t, uint64(0), kernelRecSeq(t, sc, tlsTX), "TX sequence after offload")
	assert.Equal(t, uint64(0), kernelRecSeq(t, sc, tlsRX), "RX sequence after offload")

	tx := newRecordCipher(t, clientSecret, suite) // client Finished went out under the handshake key, so app seq = 0
	rx := newRecordCipher(t, serverSecret, suite)

	// Application data under the initial key.
	_, err = raw.Write(tx.seal(recordTypeApplicationData, []byte("hello-1")))
	require.NoError(t, err)
	serverReads(t, sc, "hello-1")
	assert.Equal(t, uint64(1), kernelRecSeq(t, sc, tlsRX), "RX sequence after one record")

	return &keyUpdateConn{raw: raw, sc: sc, tx: tx, rx: rx}
}

// sendKeyUpdate emits a KeyUpdate handshake record under the current client
// traffic key.
func (k *keyUpdateConn) sendKeyUpdate(t *testing.T, requestUpdate byte) {
	t.Helper()

	_, err := k.raw.Write(k.tx.seal(recordTypeHandshake,
		[]byte{handshakeTypeKeyUpdate, 0, 0, 1, requestUpdate}))
	require.NoError(t, err)
}

func testKernelPeerKeyUpdate(t *testing.T, requestUpdate byte) {
	k := newKeyUpdateConn(t)

	// KeyUpdate under the old key, then switch and continue under the next
	// client traffic secret. The server must rekey its kernel RX path
	// (EKEYEXPIRED on kernel >= 6.14) to read hello-2.
	k.sendKeyUpdate(t, requestUpdate)
	k.tx = k.tx.next(t)
	_, err := k.raw.Write(k.tx.seal(recordTypeApplicationData, []byte("hello-2")))
	require.NoError(t, err)
	serverReads(t, k.sc, "hello-2")

	// The rekey re-armed the kernel RX state at 0; one record read since.
	assert.Equal(t, uint64(1), kernelRecSeq(t, k.sc, tlsRX), "RX sequence after rekey + one record")

	_, err = k.sc.Write([]byte("pong"))
	require.NoError(t, err)

	// TX is 1 in both variants: without update_requested pong is the first
	// record of the initial epoch; with it, our reciprocal KeyUpdate consumed
	// the old epoch's sequence, the TX rekey reset to 0, and pong made it 1.
	assert.Equal(t, uint64(1), kernelRecSeq(t, k.sc, tlsTX), "TX sequence after pong")

	if requestUpdate == keyUpdateRequested {
		// RFC 8446 section 4.6.3: the server must answer with its own
		// KeyUpdate (under its current key) before its next application data.
		innerType, payload := k.rx.open(t, readRecord(t, k.raw))
		require.Equal(t, byte(recordTypeHandshake), innerType, "expected reciprocal KeyUpdate before application data")
		assert.Equal(t, []byte{handshakeTypeKeyUpdate, 0, 0, 1, keyUpdateNotRequested}, payload)
		k.rx = k.rx.next(t)
	}

	innerType, payload := k.rx.open(t, readRecord(t, k.raw))
	require.Equal(t, byte(recordTypeApplicationData), innerType)
	assert.Equal(t, "pong", string(payload))

	// Clean client shutdown under the newest key still maps to io.EOF, and a
	// preceding warning-level user_canceled (the browser cancel flow,
	// RFC 8446 section 6.1) must be ignored, not treated as an error.
	_, err = k.raw.Write(k.tx.seal(recordTypeAlert, []byte{1, alertUserCanceled}))
	require.NoError(t, err)
	_, err = k.raw.Write(k.tx.seal(recordTypeAlert, []byte{1, alertCloseNotify}))
	require.NoError(t, err)

	n, err := k.sc.Read(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
	assert.Zero(t, n)
}

func serverReads(t *testing.T, c net.Conn, want string) {
	t.Helper()

	buf := make([]byte, 64)
	n, err := c.Read(buf)
	require.NoError(t, err)
	require.Equal(t, want, string(buf[:n]))
}

// readRecord reads one TLS record (header + body) from the raw connection.
func readRecord(t *testing.T, c net.Conn) []byte {
	t.Helper()

	hdr := make([]byte, recordHeaderLen)
	_, err := io.ReadFull(c, hdr)
	require.NoError(t, err)

	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	_, err = io.ReadFull(c, body)
	require.NoError(t, err)

	return append(hdr, body...)
}

// recordCipher seals/opens TLS 1.3 records for one direction, mirroring the
// kernel's record layer: nonce = IV XOR seq, AAD = 5-byte header, inner
// content type appended to the plaintext.
type recordCipher struct {
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
	suite  uint16
	secret []byte
}

func newRecordCipher(t *testing.T, secret []byte, suite uint16) *recordCipher {
	t.Helper()

	params, ok := cipherLookup[suite]
	require.True(t, ok, "unsupported cipher suite 0x%04x", suite)

	key, iv, err := trafficKeyIV(secret, params)
	require.NoError(t, err)

	aead, err := aeadForSuite(suite, key)
	require.NoError(t, err)

	return &recordCipher{aead: aead, iv: iv, suite: suite, secret: secret}
}

// next returns the cipher for the subsequent traffic secret (RFC 8446
// section 7.2), starting again at sequence 0.
func (rc *recordCipher) next(t *testing.T) *recordCipher {
	t.Helper()

	secret, err := deriveNextSecret(rc.secret, rc.suite)
	require.NoError(t, err)

	return newRecordCipher(t, secret, rc.suite)
}

func (rc *recordCipher) seal(innerType byte, plaintext []byte) []byte {
	inner := append(slices.Clone(plaintext), innerType)
	total := len(inner) + rc.aead.Overhead()
	hdr := []byte{recordTypeApplicationData, 3, 3, byte(total >> 8), byte(total)}

	nonce := make([]byte, rc.aead.NonceSize())
	recordNonce(nonce, rc.iv, rc.seq)
	rc.seq++

	return append(hdr, rc.aead.Seal(nil, nonce, inner, hdr)...)
}

// kernelRecSeq reads the kernel's current record sequence number for one
// direction via getsockopt(SOL_TLS, TLS_TX/TLS_RX). The kernel insists on the
// exact per-cipher struct size (anything else is EINVAL, so the generic
// unix.GetsockoptString cannot be used); rec_seq is the struct's trailing 8
// bytes, big-endian: the same layout buildCryptoInfo packs.
func kernelRecSeq(t *testing.T, c *conn, direction int) uint64 {
	t.Helper()

	params, ok := cipherLookup[c.state.CipherSuite]
	require.True(t, ok, "unsupported cipher suite 0x%04x", c.state.CipherSuite)

	buf := make([]byte, params.infoSize)
	vallen := uint32(len(buf)) //nolint:gosec // infoSize is a small constant

	rc, err := c.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, controlFD(rc, func(fd int) error {
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
			uintptr(fd), unix.SOL_TLS, uintptr(direction),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&vallen)), 0)
		if errno != 0 {
			return errno
		}

		return nil
	}))
	require.Equal(t, len(buf), int(vallen), "kernel returned unexpected crypto_info size")

	return binary.BigEndian.Uint64(buf[len(buf)-8:])
}

func (rc *recordCipher) open(t *testing.T, record []byte) (innerType byte, plaintext []byte) {
	t.Helper()

	require.GreaterOrEqual(t, len(record), recordHeaderLen)
	require.Equal(t, byte(recordTypeApplicationData), record[0], "outer record type")

	nonce := make([]byte, rc.aead.NonceSize())
	recordNonce(nonce, rc.iv, rc.seq)
	rc.seq++

	inner, err := rc.aead.Open(nil, nonce, record[recordHeaderLen:], record[:recordHeaderLen])
	require.NoError(t, err, "record did not decrypt at sequence %d", rc.seq-1)

	// Strip zero padding down to the inner content type (RFC 8446 section 5.4).
	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	require.GreaterOrEqual(t, i, 0, "record contained only padding")

	return inner[i], inner[:i]
}
