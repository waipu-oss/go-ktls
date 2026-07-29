package ktls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withTestHook registers the per-connection decision hook. Tests only; as an
// Option it is set before the accept loop starts, so there is no data race.
func withTestHook(f func(decision)) Option {
	return func(l *Listener) { l.testHookDecided = f }
}

type decisionRecorder struct {
	mu sync.Mutex
	ds []decision
}

func (r *decisionRecorder) hook(d decision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ds = append(r.ds, d)
}

func (r *decisionRecorder) all() []decision {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]decision(nil), r.ds...)
}

func testCert(tb testing.TB) tls.Certificate {
	tb.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ktls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(tb, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func newTestListener(t *testing.T, cfg *tls.Config, opts ...Option) *Listener {
	t.Helper()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	l := NewListener(inner, cfg, opts...)
	t.Cleanup(func() { _ = l.Close() })

	return l
}

// startHTTPServer serves mux on the listener and returns the base URL.
func startHTTPServer(t *testing.T, l *Listener, handler http.Handler) string {
	t.Helper()

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	return "https://" + l.Addr().String()
}

func newTestClient(t *testing.T, cfg *tls.Config, forceHTTP2 bool) *http.Client {
	t.Helper()

	if cfg.ClientSessionCache == nil {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	}

	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: forceHTTP2}
	t.Cleanup(tr.CloseIdleConnections)

	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func get(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()

	resp, err := client.Get(url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)

	return resp
}

// tlsAwareHandler fails requests that lack TLS connection info, verifying
// that net/http populates Request.TLS for both fallback and offloaded conns.
func tlsAwareHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "no TLS state", http.StatusInternalServerError)

			return
		}
		fmt.Fprintf(w, "proto=%s tls=%x", r.Proto, r.TLS.Version)
	})
}

func TestHTTP1KeepAlive(t *testing.T) {
	rec := &decisionRecorder{}
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}, NextProtos: []string{"http/1.1"}}
	l := newTestListener(t, cfg, withTestHook(rec.hook))
	url := startHTTPServer(t, l, tlsAwareHandler())

	client := newTestClient(t, &tls.Config{InsecureSkipVerify: true}, false)

	for range 3 {
		get(t, client, url) //nolint:bodyclose // get closes the body via t.Cleanup.
	}

	ds := rec.all()
	require.Len(t, ds, 1, "keep-alive must reuse the single connection")
	assert.Equal(t, 1, ds[0].rxRecords, "exactly the client Finished record must be consumed")
	assert.True(t, ds[0].reason == "" || ds[0].reason == ReasonKernel,
		"connection must be offloadable up to kernel support, got %q", ds[0].reason)
}

func TestSessionTicketRecordSequence(t *testing.T) {
	cert := testCert(t)
	outbound := &syncBuffer{}
	keyLog := &syncBuffer{}

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	decCh := make(chan decision, 1)
	l := NewListener(
		&recordingListener{Listener: inner, out: outbound},
		&tls.Config{Certificates: []tls.Certificate{cert}, KeyLogWriter: keyLog, MinVersion: tls.VersionTLS13},
		withTestHook(func(d decision) { decCh <- d }),
	)
	t.Cleanup(func() { _ = l.Close() })

	connCh := make(chan net.Conn, 1)
	go func() {
		if c, aerr := l.Accept(); aerr == nil {
			connCh <- c
		}
	}()

	clientConn, err := tls.Dial("tcp", inner.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		// A session cache makes the client offer psk_dhe_ke, so the server
		// sends a NewSessionTicket under the application traffic key during
		// Handshake(), the record the kTLS TX sequence has to account for.
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		MinVersion:         tls.VersionTLS13,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })
	require.NoError(t, clientConn.Handshake())

	var d decision
	select {
	case d = <-decCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no offload decision within 5s")
	}

	assert.Equal(t, 1, d.rxRecords, "client Finished")
	assert.Equal(t, 1, d.txRecords, "exactly one session ticket record must be counted for the TX sequence")

	suite := clientConn.ConnectionState().CipherSuite
	if suite != 0x1301 && suite != 0x1302 {
		t.Skipf("negotiated cipher suite 0x%04x is not AES-GCM, skipping decrypt check", suite)
	}

	// Prove the derivation pipeline end-to-end: decrypt the server's wire
	// output with key/IV derived from the captured traffic secret, exactly
	// like the kernel will. The one application-data record sent during the
	// handshake must decrypt at sequence 0 to a NewSessionTicket.
	secret, err := parseTrafficSecret(keyLog.String(), labelServerTraffic)
	require.NoError(t, err)

	params := cipherLookup[suite]
	key, err := hkdfExpandLabel(secret, "key", params.keyLen, params.hashFunc)
	require.NoError(t, err)
	iv, err := hkdfExpandLabel(secret, "iv", params.saltLen+params.ivLen, params.hashFunc)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	decrypted := 0
	for _, r := range splitRecords(t, outbound.Bytes()) {
		if r[0] != recordTypeApplicationData {
			continue
		}

		plaintext, oerr := aead.Open(nil, iv, r[recordHeaderLen:], r[:recordHeaderLen]) // nonce = IV XOR 0
		if oerr != nil {
			continue
		}

		decrypted++
		require.NotEmpty(t, plaintext)
		assert.Equal(t, byte(recordTypeHandshake), plaintext[len(plaintext)-1], "inner content type")
		assert.Equal(t, byte(4), plaintext[0], "handshake message type NewSessionTicket")
	}
	assert.Equal(t, 1, decrypted, "exactly one record must decrypt at TX sequence 0")

	select {
	case c := <-connCh:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no connection delivered")
	}
}

// TestSessionTicketsDisabledFallsBackToUserspace pins the trade documented in
// computeTXSeq: with no NewSessionTicket the last written record is the
// handshake-key Finished, which opens under no application sequence. computeTXSeq
// cannot tell this legitimate zero-record case apart from a ≥2-record layout
// without a TX record count, so it fails closed and the connection falls back to
// userspace (ReasonFraming) rather than offloading at TX sequence 0.
func TestSessionTicketsDisabledFallsBackToUserspace(t *testing.T) {
	rec := &decisionRecorder{}
	cfg := &tls.Config{
		Certificates:           []tls.Certificate{testCert(t)},
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS13,
	}
	l := newTestListener(t, cfg, withTestHook(rec.hook))
	url := startHTTPServer(t, l, tlsAwareHandler())

	client := newTestClient(t, &tls.Config{InsecureSkipVerify: true}, false)
	get(t, client, url) //nolint:bodyclose // get closes the body via t.Cleanup.

	ds := rec.all()
	require.Len(t, ds, 1)
	assert.Equal(t, ReasonFraming, ds[0].reason,
		"no-ticket TLS 1.3 opens at no application sequence, so it fails closed to userspace")
}

func TestHTTP2StaysInUserspace(t *testing.T) {
	rec := &decisionRecorder{}
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}, NextProtos: []string{"h2", "http/1.1"}}
	l := newTestListener(t, cfg, withTestHook(rec.hook))
	url := startHTTPServer(t, l, tlsAwareHandler())

	client := newTestClient(t, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, true)
	resp := get(t, client, url) //nolint:bodyclose // get closes the body via t.Cleanup.

	assert.Equal(t, 2, resp.ProtoMajor, "HTTP/2 must keep working through the fallback *tls.Conn")

	ds := rec.all()
	require.Len(t, ds, 1)
	assert.Equal(t, ReasonALPN, ds[0].reason)
}

func TestTLS12Offloadable(t *testing.T) {
	rec := &decisionRecorder{}
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}, MinVersion: tls.VersionTLS12}
	l := newTestListener(t, cfg, withTestHook(rec.hook))
	url := startHTTPServer(t, l, tlsAwareHandler())

	client := newTestClient(t, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, false)
	get(t, client, url) //nolint:bodyclose // get closes the body via t.Cleanup.

	ds := rec.all()
	require.Len(t, ds, 1)
	assert.True(t, ds[0].reason == "" || ds[0].reason == ReasonKernel,
		"TLS 1.2 AES-GCM must be offloadable up to kernel support, got %q", ds[0].reason)
	assert.Equal(t, 0, ds[0].rxRecords, "TLS 1.2 client Finished is a handshake record, not app data")
	assert.Equal(t, 1, ds[0].txRecords, "TLS 1.2 TX continues after the server Finished")
}

// tls12ResumeDialer starts a TLS 1.2-only listener, drains accepted conns so the
// handshake goroutines do not block on Accept, and returns a dialer sharing one
// client session cache so successive calls resume.
func tls12ResumeDialer(t *testing.T, opts ...Option) func() (tls.ConnectionState, decision) {
	t.Helper()

	decCh := make(chan decision, 1)
	l := newTestListener(t,
		&tls.Config{
			Certificates: []tls.Certificate{testCert(t)},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		},
		append(opts, withTestHook(func(d decision) { decCh <- d }))...,
	)

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	cache := tls.NewLRUClientSessionCache(8)

	return func() (tls.ConnectionState, decision) {
		t.Helper()

		conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
			ClientSessionCache: cache,
		})
		require.NoError(t, err)
		require.NoError(t, conn.Handshake())
		st := conn.ConnectionState()
		_ = conn.Close()

		select {
		case d := <-decCh:
			return st, d
		case <-time.After(5 * time.Second):
			t.Fatal("no offload decision within 5s")

			return st, decision{}
		}
	}
}

// TestTLS12ResumptionOffloadable proves a resumed TLS 1.2 session stays
// offloadable. crypto/tls logs CLIENT_RANDOM only on a full handshake, so the
// abbreviated resumption flow leaves the key-log sniffer empty; the master
// secret is recovered by decrypting the presented ticket (UnwrapSession) and
// the client random is taken from the wire. The resumed connection's decision
// must be offloadable (or ReasonKernel where kTLS is absent), never
// ReasonSecrets, that is the regression this guards.
func TestTLS12ResumptionOffloadable(t *testing.T) {
	dial := tls12ResumeDialer(t)

	// First handshake: full, issues and caches the ticket (master via key log).
	first, firstDec := dial()
	require.False(t, first.DidResume, "first handshake must not resume")
	assert.True(t, firstDec.reason == "" || firstDec.reason == ReasonKernel,
		"full TLS 1.2 handshake must be offloadable, got %q", firstDec.reason)

	// Second handshake: abbreviated, resumes from the cached ticket.
	second, secondDec := dial()
	require.True(t, second.DidResume, "second handshake must resume the TLS 1.2 session")
	assert.NotEqual(t, ReasonSecrets, secondDec.reason,
		"resumed session must recover the master secret from the ticket, not fall back")
	assert.True(t, secondDec.reason == "" || secondDec.reason == ReasonKernel,
		"resumed TLS 1.2 must be offloadable via the recovered master secret, got %q", secondDec.reason)

	// Third handshake: resumes from the ticket the resumed second one re-issued,
	// which was minted with an empty key log.
	third, thirdDec := dial()
	require.True(t, third.DidResume, "third handshake must resume")
	assert.NotEqual(t, ReasonSecrets, thirdDec.reason,
		"a re-issued ticket must carry the master too, or the chain loses offload from here on")
	assert.True(t, thirdDec.reason == "" || thirdDec.reason == ReasonKernel,
		"third handshake in a resumption chain must still be offloadable, got %q", thirdDec.reason)
}

// TestCustomSessionHooksNotOverridden guards the gate that keeps us from
// clobbering a caller-supplied ticket scheme: when the config already carries
// WrapSession/UnwrapSession, NewListener must leave them in place and not take
// over ticket management (which would issue/redeem tickets the caller cannot
// decrypt). This pins the WrapSession==nil && UnwrapSession==nil condition.
func TestCustomSessionHooksNotOverridden(t *testing.T) {
	wrap := func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return []byte("x"), nil }
	unwrap := func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil }

	l := newTestListener(t, &tls.Config{
		Certificates:  []tls.Certificate{testCert(t)},
		MinVersion:    tls.VersionTLS12,
		WrapSession:   wrap,
		UnwrapSession: unwrap,
	})

	assert.False(t, l.manageTickets,
		"a caller-supplied ticket scheme must disable our ticket management")
	assert.Equal(t, reflect.ValueOf(wrap).Pointer(), reflect.ValueOf(l.cfg.WrapSession).Pointer(),
		"caller WrapSession must not be overwritten by EncryptTicket")
	assert.Equal(t, reflect.ValueOf(unwrap).Pointer(), reflect.ValueOf(l.cfg.UnwrapSession).Pointer(),
		"caller UnwrapSession must be preserved")
}

// The gate exists to enable kTLS without a restart, so tickets minted while it
// is closed must be offloadable the moment it opens.
func TestTLS12TicketFromClosedGateStaysRecoverable(t *testing.T) {
	var open atomic.Bool
	dial := tls12ResumeDialer(t, WithOffloadGate(open.Load))

	_, closedDec := dial()
	require.Equal(t, ReasonFeatureDisabled, closedDec.reason, "gate is closed")

	open.Store(true)

	resumed, openDec := dial()
	require.True(t, resumed.DidResume, "second handshake must resume the ticket issued while closed")
	assert.NotEqual(t, ReasonSecrets, openDec.reason,
		"a ticket issued behind a closed gate must still be recoverable once it opens")
	assert.True(t, openDec.reason == "" || openDec.reason == ReasonKernel,
		"resumption after opening the gate must be offloadable, got %q", openDec.reason)
}

func TestOldTLSVersionsStayInUserspace(t *testing.T) {
	l := &Listener{cfg: &tls.Config{}}

	reason := l.offloadDecision(tls.ConnectionState{Version: tls.VersionTLS10}, &framedConn{})
	assert.Equal(t, ReasonTLSVersion, reason)
}

// TestTLS12FinishedRecordDecrypt is the TLS 1.2 counterpart of the session
// ticket test: it decrypts the server Finished record off the wire using the
// key material packCryptoInfo12 produces (what the kernel, or the NIC via
// TLS_HW, uses), validating the PRF, key-block split, fixed IV and
// AAD/sequence conventions against crypto/tls. The Finished is
// the server's only encrypted record during the handshake (sequence 0),
// which is also why the TX sequence continues at 1.
func TestTLS12FinishedRecordDecrypt(t *testing.T) {
	cert := testCert(t)
	outbound := &syncBuffer{}
	keyLog := &syncBuffer{}

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	decCh := make(chan decision, 1)
	l := NewListener(
		&recordingListener{Listener: inner, out: outbound},
		&tls.Config{Certificates: []tls.Certificate{cert}, KeyLogWriter: keyLog, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
		withTestHook(func(d decision) { decCh <- d }),
	)
	t.Cleanup(func() { _ = l.Close() })

	connCh := make(chan net.Conn, 1)
	go func() {
		if c, aerr := l.Accept(); aerr == nil {
			connCh <- c
		}
	}()

	clientConn, err := tls.Dial("tcp", inner.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })
	require.NoError(t, clientConn.Handshake())

	var d decision
	select {
	case d = <-decCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no offload decision within 5s")
	}

	assert.Equal(t, 0, d.rxRecords)
	assert.Equal(t, 1, d.txRecords)

	suite := clientConn.ConnectionState().CipherSuite
	params, ok := tls12CipherLookup[suite]
	require.True(t, ok, "negotiated suite 0x%04x must be an offloadable AES-GCM suite", suite)

	// Recover the key material exactly the way the listener does.
	sniffer := &keyLogSniffer{}
	_, err = sniffer.Write([]byte(keyLog.String()))
	require.NoError(t, err)
	clientRandom, masterSecret, err := sniffer.masterSecret()
	require.NoError(t, err)

	records := splitRecords(t, outbound.Bytes())
	require.NotEmpty(t, records)
	require.Equal(t, byte(recordTypeHandshake), records[0][0], "first outbound record is the ServerHello")
	serverRandom := records[0][recordHeaderLen+6 : recordHeaderLen+38]

	keyBlock, err := tls12KeyBlock(masterSecret, clientRandom, serverRandom, params)
	require.NoError(t, err)

	txInfo := packCryptoInfo12(params, keyBlock, true, 1)

	// Extract key/salt from the packed kernel struct (header(4) + iv(8) + key
	// + salt), independently of writeKeyIV, so this is a genuine cross-check of
	// the packing layout against crypto/tls.
	key := txInfo[12 : 12+params.keyLen]
	salt := txInfo[12+params.keyLen : 12+params.keyLen+tls12SaltLen]

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	// The server Finished is the first handshake record after the outbound
	// ChangeCipherSpec; record format: explicit_nonce(8) || ciphertext || tag.
	var finished []byte
	seenCCS := false
	for _, r := range records {
		if r[0] == recordTypeChangeCipherSpec {
			seenCCS = true

			continue
		}
		if seenCCS && r[0] == recordTypeHandshake {
			finished = r

			break
		}
	}
	require.NotNil(t, finished, "no encrypted record after the ChangeCipherSpec")

	body := finished[recordHeaderLen:]
	require.Greater(t, len(body), tls12IVLen+16)

	nonce := append(append([]byte{}, salt...), body[:tls12IVLen]...)
	ciphertext := body[tls12IVLen:]

	// additional_data = seq_num(8) || type(1) || version(2) || plaintext length(2); seq 0.
	aad := make([]byte, 13)
	aad[8] = recordTypeHandshake
	aad[9], aad[10] = 3, 3
	plaintextLen := len(ciphertext) - 16
	aad[11], aad[12] = byte(plaintextLen>>8), byte(plaintextLen)

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	require.NoError(t, err, "server Finished must decrypt with the derived server-write key at sequence 0")
	require.NotEmpty(t, plaintext)
	assert.Equal(t, byte(20), plaintext[0], "handshake message type Finished")

	// The production pre-offload check must agree on the real Finished.
	assert.True(t, verifyServerFinished(body, keyBlock, params),
		"verifyServerFinished must confirm the derived keys against the wire Finished")

	select {
	case c := <-connCh:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no connection delivered")
	}
}

func TestSlowClientDoesNotBlockAccept(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}}
	l := newTestListener(t, cfg, WithHandshakeTimeout(2*time.Second))
	url := startHTTPServer(t, l, tlsAwareHandler())

	// A connection that never starts its handshake...
	idle, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = idle.Close() })

	// ...must not stop other clients from being served.
	start := time.Now()
	client := newTestClient(t, &tls.Config{InsecureSkipVerify: true}, false)
	get(t, client, url) //nolint:bodyclose // get closes the body via t.Cleanup.
	assert.Less(t, time.Since(start), 2*time.Second, "request must not wait for the idle connection's handshake")
}

func TestHandshakeTimeoutClosesConnection(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}}
	l := newTestListener(t, cfg, WithHandshakeTimeout(150*time.Millisecond))

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	start := time.Now()
	_, err = io.ReadAll(conn)
	elapsed := time.Since(start)

	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		t.Fatalf("connection was not closed by the listener within %s", elapsed)
	}
	assert.Less(t, elapsed, 3*time.Second)
}

// TestHandshakePanicRecovered verifies that a panic in the handshake goroutine
// (which parses attacker-controlled bytes outside net/http's per-connection
// recover) is contained: the connection is dropped and reported, but the accept
// loop and the process survive. A synthetic panic is injected via the decision
// hook, which runs inside the handshake goroutine.
func TestHandshakePanicRecovered(t *testing.T) {
	var panicOnce, obsOnce sync.Once
	reasons := make(chan string, 4)

	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}, MinVersion: tls.VersionTLS13}
	l := newTestListener(t, cfg,
		// The observer panics on the ReasonPanic report itself, the fatal path.
		WithObserver(func(reason string, _ net.Addr, _ tls.ConnectionState, _ error) {
			reasons <- reason
			obsOnce.Do(func() { panic("synthetic observer panic") })
		}),
		withTestHook(func(decision) { panicOnce.Do(func() { panic("synthetic handshake panic") }) }),
	)

	connCh := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			connCh <- c
		}
	}()

	// First connection: the server handshake goroutine panics in the hook. The
	// panic fires after the TLS handshake completes, so the client Dial result
	// is timing-dependent and not asserted; the recover path is what matters.
	if c1, err := tls.Dial("tcp", l.Addr().String(),
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}); err == nil {
		t.Cleanup(func() { _ = c1.Close() })
	}

	select {
	case r := <-reasons:
		require.Equal(t, ReasonPanic, r, "recovered panic must be reported to the observer")
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not report the recovered panic")
	}

	// The accept loop and process survived: a second handshake completes and the
	// connection is delivered through Accept.
	c2, err := tls.Dial("tcp", l.Addr().String(),
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c2.Close() })
	require.NoError(t, c2.Handshake())

	select {
	case <-connCh:
	case <-time.After(5 * time.Second):
		t.Fatal("second connection was not accepted after the recovered panic")
	}
}

// TestFallbackConnUnwrapsToTCPConn pins the contract conninfo relies on for
// TCP_INFO collection: the conn returned from Accept can be unwrapped to the
// raw *net.TCPConn via NetConn (through the framedConn on the fallback path).
//
// It uses an h2 ALPN fallback, which always stays in userspace (net/http needs
// a concrete *tls.Conn for HTTP/2) regardless of kernel kTLS support, so the
// fallback path is exercised on every platform, including a real kTLS kernel
// where TLS 1.2/1.3 would otherwise be offloaded.
func TestFallbackConnUnwrapsToTCPConn(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}, NextProtos: []string{"h2", "http/1.1"}}
	l := newTestListener(t, cfg)

	connCh := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			connCh <- c
		}
	}()

	clientConn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	var serverConn net.Conn
	select {
	case serverConn = <-connCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection delivered")
	}
	t.Cleanup(func() { _ = serverConn.Close() })

	_, isTLS := serverConn.(*tls.Conn)
	require.True(t, isTLS, "h2 ALPN fallback must be a *tls.Conn")

	type netConner interface{ NetConn() net.Conn }

	conn := serverConn
	for range 4 {
		if _, ok := conn.(*net.TCPConn); ok {
			return // reached the raw connection
		}

		wrapper, ok := conn.(netConner)
		require.True(t, ok, "conn %T must expose NetConn for unwrapping", conn)
		conn = wrapper.NetConn()
	}

	require.IsType(t, &net.TCPConn{}, conn)
}

// TestSessionResumptionSharesTicketKeys pins the fix for the per-connection
// config clone breaking resumption: a second connection must resume the first
// via a shared ticket key. Resumption is decided in the userspace handshake,
// so this is platform-independent (offload or fallback).
func TestSessionResumptionSharesTicketKeys(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}, MinVersion: tls.VersionTLS13}
	l := newTestListener(t, cfg)

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				buf := make([]byte, 16)
				n, rerr := c.Read(buf)
				if rerr == nil {
					_, _ = c.Write(buf[:n])
				}
			}(c)
		}
	}()

	cache := tls.NewLRUClientSessionCache(8)
	dial := func() tls.ConnectionState {
		t.Helper()
		conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			MinVersion:         tls.VersionTLS13,
			ClientSessionCache: cache,
		})
		require.NoError(t, err)
		defer conn.Close() //nolint:errcheck
		// Drive a write+read so the client processes the post-handshake
		// NewSessionTicket and caches it.
		_, _ = conn.Write([]byte("ping\n"))
		_, _ = conn.Read(make([]byte, 16))

		return conn.ConnectionState()
	}

	require.False(t, dial().DidResume, "first connection cannot resume")
	assert.True(t, dial().DidResume,
		"second connection must resume: per-connection clones must share the ticket key")
}

func TestTicketKeyRotationDropsExpired(t *testing.T) {
	l := &Listener{cfg: &tls.Config{}}
	l.ticketKeys = []stampedTicketKey{
		{created: time.Now().Add(-8 * 24 * time.Hour)}, // expired (> 7d lifetime)
		{created: time.Now().Add(-1 * time.Hour)},      // still valid
	}

	l.rotateTicketKeys()

	// Fresh key prepended, expired one dropped, valid one kept.
	require.Len(t, l.ticketKeys, 2)
	assert.WithinDuration(t, time.Now(), l.ticketKeys[0].created, time.Minute, "newest key is first")
}

func TestAcceptAfterClose(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}}
	l := newTestListener(t, cfg)

	require.NoError(t, l.Close())

	_, err := l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestFatalAcceptErrorStopsListener guards against the accept loop leaking on a
// persistent, terminal Accept error: the loop must surface it once and tear the
// listener down rather than block forever on the next errc send. goleak in
// TestMain catches the leak (of acceptLoop and ticketRotationLoop) if it
// regresses.
func TestFatalAcceptErrorStopsListener(t *testing.T) {
	boom := errors.New("accept failed permanently")
	inner := &scriptedListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, errs: []error{boom}}

	l := NewListener(inner, &tls.Config{Certificates: []tls.Certificate{testCert(t)}})
	t.Cleanup(func() { _ = l.Close() })

	_, err := l.Accept()
	require.ErrorIs(t, err, boom)

	// The accept loop closed the listener on the terminal error, so a second
	// Accept observes the closed state instead of hanging.
	_, err = l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestTransientAcceptErrorKeepsAccepting verifies fd-exhaustion errors are
// forwarded to the caller (like a stock net.Listener, so net/http backs off and
// retries) without stopping the accept loop, which keeps serving the next
// Accept until a terminal error tears it down.
func TestTransientAcceptErrorKeepsAccepting(t *testing.T) {
	fatal := errors.New("permanent")
	inner := &scriptedListener{
		addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		errs: []error{syscall.EMFILE, fatal},
	}

	l := NewListener(inner, &tls.Config{Certificates: []tls.Certificate{testCert(t)}})
	t.Cleanup(func() { _ = l.Close() })

	_, err := l.Accept()
	require.ErrorIs(t, err, syscall.EMFILE) // transient error surfaced, not swallowed

	_, err = l.Accept()
	require.ErrorIs(t, err, fatal) // loop kept going and surfaced the next error

	_, err = l.Accept()
	require.ErrorIs(t, err, net.ErrClosed) // terminal error tore the listener down
}

// --- helpers ---

// scriptedListener is a net.Listener that never yields a connection: Accept
// returns the errors in errs in order (the last one repeating) and counts
// calls. Used to drive the accept loop's error handling deterministically.
type scriptedListener struct {
	addr net.Addr
	errs []error

	mu sync.Mutex
	n  int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	i := min(l.n, len(l.errs)-1)
	l.n++

	return nil, l.errs[i]
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return l.addr }

// syncBuffer is a goroutine-safe byte buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)

	return len(p), nil
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]byte(nil), b.buf...)
}

func (b *syncBuffer) String() string {
	return string(b.Bytes())
}

// recordingListener tees all server-to-client bytes into out.
type recordingListener struct {
	net.Listener

	out *syncBuffer
}

func (r *recordingListener) Accept() (net.Conn, error) {
	c, err := r.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &teeConn{Conn: c, out: r.out}, nil
}

type teeConn struct {
	net.Conn

	out *syncBuffer
}

func (c *teeConn) Write(b []byte) (int, error) {
	_, _ = c.out.Write(b)

	return c.Conn.Write(b)
}

// splitRecords parses a raw TLS byte stream into complete records
// (header + body each).
func splitRecords(t *testing.T, data []byte) [][]byte {
	t.Helper()

	var recs [][]byte
	for len(data) >= recordHeaderLen {
		bodyLen := int(data[3])<<8 | int(data[4])
		require.GreaterOrEqual(t, len(data), recordHeaderLen+bodyLen, "truncated record in stream")
		recs = append(recs, data[:recordHeaderLen+bodyLen])
		data = data[recordHeaderLen+bodyLen:]
	}
	require.Empty(t, data, "trailing bytes after last record")

	return recs
}
