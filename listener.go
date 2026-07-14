package ktls

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
)

const (
	defaultHandshakeTimeout = 10 * time.Second

	// Session ticket key rotation, mirroring crypto/tls' own auto-rotation
	// (which the per-connection config clone disables): rotate the encryption
	// key daily, keep older keys for a week so recently issued tickets still
	// decrypt. Without this, every cloned config would generate its own key
	// and cross-connection resumption would never succeed.
	defaultTicketKeyRotation = 24 * time.Hour
	ticketKeyLifetime        = 7 * 24 * time.Hour
)

// Fallback / event reasons reported to the observer (see WithObserver).
const (
	ReasonHandshakeError  = "handshake-error"
	ReasonPanic           = "panic"            // recovered panic in the handshake goroutine
	ReasonTLSVersion      = "tls-version"      // < TLS 1.2, stays in userspace
	ReasonALPN            = "alpn"             // h2 negotiated; net/http needs a *tls.Conn for HTTP/2
	ReasonClientAuth      = "client-auth"      // client certificates configured, not offloaded
	ReasonKernel          = "kernel"           // kTLS unavailable (module missing or non-Linux)
	ReasonFeatureDisabled = "feature-disabled" // offload turned off at runtime via the gate (feature flag)
	ReasonCipher          = "cipher"           // negotiated cipher suite not offloadable (e.g. TLS 1.2 CBC)
	ReasonFraming         = "framing"          // unexpected record layout during handshake
	ReasonSecrets         = "secrets"          // key material not captured (e.g. GetConfigForClient)
	ReasonSetsockopt      = "setsockopt"       // kernel rejected the offload, clean fallback
	ReasonConnUnusable    = "conn-unusable"    // partial offload, connection closed
	reasonOffloaded       = "offloaded"        // success (observer sees it with nil error)
)

// offloadKeys carries the prepared kernel crypto_info blobs for both
// directions, plus the TLS 1.3 traffic secrets for later key updates
// (nil for TLS 1.2, which has no KeyUpdate).
type offloadKeys struct {
	tx, rx             []byte
	txSecret, rxSecret []byte
}

// Conn is implemented by connections returned from Accept when kTLS offload
// is active. Fallback connections are plain *tls.Conn instead. net/http
// populates Request.TLS through the ConnectionState method; NetConn mirrors
// (*tls.Conn).NetConn for callers unwrapping to the raw TCP connection.
type Conn interface {
	net.Conn
	syscall.Conn

	ConnectionState() tls.ConnectionState
	NetConn() net.Conn
}

// Listener accepts TCP connections, performs the TLS handshake in userspace
// and hands the established TLS 1.2 or 1.3 session keys to the kernel. Each handshake
// runs in its own goroutine (mirroring net/http's connection-per-goroutine
// model, since the offload requires the handshake to complete before the conn
// reaches net/http); Accept returns fully established connections (either
// kTLS-offloaded or *tls.Conn fallbacks).
type Listener struct {
	inner net.Listener
	cfg   *tls.Config

	handshakeTimeout time.Duration
	observer         func(reason string, remoteAddr net.Addr, state tls.ConnectionState, err error)
	gate             func() bool // per-connection offload gate; nil = always offload

	connc chan net.Conn
	errc  chan error
	done  chan struct{}

	closeOnce sync.Once
	closeErr  error

	// Session ticket keys, rotated by ticketRotationLoop and installed on the
	// base config via l.cfg.SetSessionTicketKeys. Per-connection clones hold no
	// keys; their WrapSession/UnwrapSession route ticket crypto back through
	// l.cfg (l.cfg.EncryptTicket / l.cfg.DecryptTicket) so all connections share
	// one ring. ticketRotation == 0 disables our management (the config is left
	// as-is).
	ticketRotation time.Duration
	ticketMu       sync.Mutex
	ticketKeys     []stampedTicketKey // newest first

	// manageTickets is set when we own ticket issuance/redemption via
	// WrapSession/UnwrapSession, which is what lets UnwrapSession recover the
	// TLS 1.2 master secret from resumed tickets.
	manageTickets bool

	// testHookDecided is invoked (when set) after the offload decision for a
	// connection has been made, before the offload syscalls. Tests only;
	// production observability flows through the observer.
	testHookDecided func(d decision)
}

// decision captures the per-connection offload decision for the test hook.
type decision struct {
	reason string // empty when offloadable
	// txRecords is the kernel TX start sequence: for TLS 1.3 the count of
	// application-data records (session tickets) sent during the handshake;
	// for TLS 1.2 always 1 (continues after the server Finished).
	txRecords int
	rxRecords int // application-data records consumed during handshake (TLS 1.3 client Finished)
}

// Option configures a Listener.
type Option func(*Listener)

// WithHandshakeTimeout bounds the duration of the userspace handshake
// (default 10s). Connections exceeding it are closed.
func WithHandshakeTimeout(d time.Duration) Option {
	return func(l *Listener) { l.handshakeTimeout = d }
}

// WithObserver registers a callback invoked once per connection with the
// offload outcome: reason "offloaded" with a nil error on success, otherwise
// one of the Reason* constants (err may be nil, e.g. for ALPN fallbacks). The
// connection state carries the negotiated TLS version and cipher suite for
// labelling (zero value on a handshake error, before any negotiation), and
// remoteAddr identifies the peer (e.g. for handshake-error logs matching
// net/http's "TLS handshake error from <addr>" format).
// Useful for metrics. Must be safe for concurrent use.
func WithObserver(f func(reason string, remoteAddr net.Addr, state tls.ConnectionState, err error)) Option {
	return func(l *Listener) { l.observer = f }
}

// WithOffloadGate sets a predicate consulted per connection: when it returns
// false the connection falls back to userspace TLS (reported as
// ReasonFeatureDisabled), so an external runtime switch (e.g. a feature flag)
// can disable kTLS without a restart. Already-offloaded connections are
// unaffected. nil/unset means always offload. fn must be safe for concurrent
// use.
func WithOffloadGate(fn func() bool) Option {
	return func(l *Listener) { l.gate = fn }
}

// NewListener wraps inner. cfg is used for the userspace handshake and must
// be non-nil with a certificate source configured.
func NewListener(inner net.Listener, cfg *tls.Config, opts ...Option) *Listener {
	if cfg == nil {
		panic("ktls: nil tls.Config")
	}

	l := &Listener{
		inner: inner,
		// Own a base clone: per-connection clones (for the KeyLogWriter) and
		// our session-ticket-key management mutate this, never the caller's.
		cfg:              cfg.Clone(),
		handshakeTimeout: defaultHandshakeTimeout,
		ticketRotation:   defaultTicketKeyRotation,
		connc:            make(chan net.Conn), // unbuffered: no established conns get orphaned on Close
		errc:             make(chan error),
		done:             make(chan struct{}),
	}

	for _, opt := range opts {
		opt(l)
	}

	// Seed and rotate session ticket keys so all per-connection config clones
	// share them; otherwise each clone auto-generates its own and resumption
	// never works. Skipped when tickets are disabled, or when the caller brought
	// its own ticket scheme, we must not clobber that, and can only recover the
	// master secret from tickets we issued. setupConn installs the per-connection
	// WrapSession/UnwrapSession over l.cfg's EncryptTicket/DecryptTicket.
	if l.ticketRotation > 0 && !l.cfg.SessionTicketsDisabled &&
		l.cfg.WrapSession == nil && l.cfg.UnwrapSession == nil {
		l.manageTickets = true

		l.rotateTicketKeys()

		go l.ticketRotationLoop()
	}

	go l.acceptLoop()

	return l
}

// stampedTicketKey pairs a session ticket encryption key with its creation
// time, so rotation can expire keys past their lifetime.
type stampedTicketKey struct {
	key     [32]byte
	created time.Time
}

// rotateTicketKeys prepends a fresh key, drops keys past their lifetime, and
// pushes the resulting ring (newest first) into the base config. crypto/tls
// encrypts new tickets with the first key and can decrypt with any in the
// ring, so day-old tickets still resume across a rotation.
func (l *Listener) rotateTicketKeys() {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return // keep the existing ring; rotation retries next tick
	}

	now := time.Now()

	l.ticketMu.Lock()
	kept := []stampedTicketKey{{key: key, created: now}}
	for _, sk := range l.ticketKeys {
		if now.Sub(sk.created) < ticketKeyLifetime {
			kept = append(kept, sk)
		}
	}
	l.ticketKeys = kept

	ring := make([][32]byte, len(kept))
	for i, sk := range kept {
		ring[i] = sk.key
	}
	l.ticketMu.Unlock()

	l.cfg.SetSessionTicketKeys(ring)
}

func (l *Listener) ticketRotationLoop() {
	t := time.NewTicker(l.ticketRotation)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			l.rotateTicketKeys()
		case <-l.done:
			return
		}
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connc:
		return c, nil
	case err := <-l.errc:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.inner.Close()
	})

	return l.closeErr
}

func (l *Listener) Addr() net.Addr {
	return l.inner.Addr()
}

func (l *Listener) acceptLoop() {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			// Forward to the Accept caller (net/http's Serve) and let it do the
			// backoff/retry, like any net.Listener.
			select {
			case l.errc <- err:
			case <-l.done:
				return
			}

			// Serve keeps draining errc only while it retries (EMFILE/ENFILE);
			// on anything else it returns, so we must stop too or the next send
			// leaks this goroutine and ticketRotationLoop. EINTR/ECONNABORTED/
			// EAGAIN never reach us: poll.FD.Accept retries them.
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
				continue
			}

			_ = l.Close()

			return
		}

		// One goroutine per connection, like net/http's accept loop: a slow or
		// stalled handshake never blocks accepting new connections. The
		// handshake is bounded by handshakeTimeout (set in setupConn).
		go l.handshake(raw)
	}
}

func (l *Listener) handshake(raw net.Conn) {
	// This goroutine runs the handshake and record/key parsing of
	// attacker-controlled bytes outside net/http's per-connection recover (the
	// offload requires the handshake to finish before the conn reaches
	// net/http). Without this, a single unanticipated panic in that parsing
	// would crash the whole edge process. Mirror net/http's conn.serve: recover,
	// report, close the connection, and let the rest of the server keep running.
	defer func() {
		if r := recover(); r != nil {
			// err carries the panic value and stack; the consumer (observer)
			// supplies the "panic" wording via ReasonPanic, mirroring how the
			// handshake-error path leaves the message to the caller.
			l.observe(ReasonPanic, raw.RemoteAddr(), tls.ConnectionState{},
				fmt.Errorf("%v\n%s", r, debug.Stack()))
			_ = raw.Close()
		}
	}()

	conn, err := l.setupConn(raw)
	if err != nil {
		_ = raw.Close()

		return
	}

	select {
	case l.connc <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

// setupConn performs the userspace handshake and either offloads the session
// to the kernel or falls back to the *tls.Conn. A non-nil error means the
// connection is unusable and must be closed.
func (l *Listener) setupConn(raw net.Conn) (net.Conn, error) {
	_ = raw.SetDeadline(time.Now().Add(l.handshakeTimeout))

	framed := &framedConn{Conn: raw}
	sniffer := &keyLogSniffer{chain: l.cfg.KeyLogWriter}

	cfg := l.cfg.Clone()
	cfg.KeyLogWriter = sniffer

	// Resumed TLS 1.2 logs no CLIENT_RANDOM: WrapSession stashes the master (still
	// in the key log at full-handshake issue) in the ticket's Extra field, and
	// UnwrapSession reads it back. recoveredMaster is written in UnwrapSession and
	// read by prepareKeys after Handshake(), both on this goroutine, so no locking.
	var recoveredMaster []byte
	if l.manageTickets {
		cfg.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
			// Only offloadable TLS 1.2 needs this (skip 1.3 PSK / gate-off tickets).
			if l.recoverableTLS12(cs.Version) {
				if _, master, err := sniffer.masterSecret(); err == nil {
					appendMasterExtra(ss, master)
				}
			}

			// Encrypt via l.cfg so every per-connection clone shares the one
			// rotating ticket key ring (rotateTicketKeys updates l.cfg).
			return l.cfg.EncryptTicket(cs, ss)
		}
		cfg.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
			ss, err := l.cfg.DecryptTicket(identity, cs)
			if err != nil || ss == nil {
				return ss, err
			}
			if l.recoverableTLS12(cs.Version) {
				if master, ok := masterFromExtra(ss); ok {
					recoveredMaster = master
				}
			}

			return ss, nil
		}
	}

	tlsConn := tls.Server(framed, cfg)
	if err := tlsConn.Handshake(); err != nil {
		l.observe(ReasonHandshakeError, raw.RemoteAddr(), tls.ConnectionState{}, err)

		return nil, err
	}

	_ = raw.SetDeadline(time.Time{})

	state := tlsConn.ConnectionState()
	reason := l.offloadDecision(state, framed)

	var (
		reasonErr error
		txSeq     uint64
		keys      offloadKeys
	)

	if reason == "" {
		var err error
		if keys, txSeq, err = l.prepareKeys(state, framed, sniffer, recoveredMaster); err != nil {
			if reason = ReasonSecrets; errors.Is(err, errFraming) {
				reason = ReasonFraming
			}
			reasonErr = err
		} else if !Available() {
			reason = ReasonKernel
		}
	}

	if l.testHookDecided != nil {
		l.testHookDecided(decision{reason: reason, txRecords: int(txSeq), rxRecords: framed.rxApp}) //nolint:gosec // tiny
	}

	if reason != "" {
		framed.release()
		l.observe(reason, raw.RemoteAddr(), state, reasonErr)

		return tlsConn, nil
	}

	kc, err := offload(raw, state, keys)
	switch {
	case err == nil:
		l.observe(reasonOffloaded, raw.RemoteAddr(), state, nil)

		return kc, nil
	case errors.Is(err, errConnUnusable):
		// TX is already offloaded; userspace TLS can no longer drive this socket.
		l.observe(ReasonConnUnusable, raw.RemoteAddr(), state, err)

		return nil, err
	default:
		framed.release()
		l.observe(ReasonSetsockopt, raw.RemoteAddr(), state, err)

		return tlsConn, nil
	}
}

// offloadGateOpen reports whether the runtime gate (feature flag) allows
// offload. Not gated on Available(): a kTLS-less node still runs the recovery
// so the fallback is attributed to ReasonKernel, not ReasonSecrets.
func (l *Listener) offloadGateOpen() bool {
	return l.gate == nil || l.gate()
}

// recoverableTLS12 reports whether this connection is an offloadable TLS 1.2
// session whose ticket should carry (and recover) the master secret.
func (l *Listener) recoverableTLS12(version uint16) bool {
	return version == tls.VersionTLS12 && l.offloadGateOpen()
}

// offloadDecision returns the empty string when the connection should be
// offloaded, or the fallback reason. The kernel support check happens last,
// in setupConn, so the decision data is identical across platforms.
func (l *Listener) offloadDecision(state tls.ConnectionState, framed *framedConn) string {
	// Runtime gate (feature flag) checked first: when off, every new connection
	// falls back to userspace TLS regardless of its other properties.
	if l.gate != nil && !l.gate() {
		return ReasonFeatureDisabled
	}

	// net/http only enables HTTP/2 on concrete *tls.Conn values, so h2
	// connections must stay in userspace TLS.
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return ReasonALPN
	}

	if l.cfg.ClientAuth != tls.NoClientCert {
		return ReasonClientAuth
	}

	// Reject unsupported versions first, so the observer attributes them to
	// tls-version rather than to a later framing/cipher check.
	if state.Version != tls.VersionTLS13 && state.Version != tls.VersionTLS12 {
		return ReasonTLSVersion
	}

	if !framed.readAtBoundary() {
		return ReasonFraming
	}

	switch state.Version {
	case tls.VersionTLS13:
		if _, ok := cipherLookup[state.CipherSuite]; !ok {
			return ReasonCipher
		}

		// Exactly one application-data record (the client Finished, disguised
		// as application data on the wire) must have been consumed. Anything
		// else means a protocol flow we did not anticipate; stay in userspace.
		if framed.rxApp != 1 {
			return ReasonFraming
		}
	case tls.VersionTLS12:
		if _, ok := tls12CipherLookup[state.CipherSuite]; !ok {
			return ReasonCipher
		}

		// TLS 1.2 does not disguise record types: the client Finished is a
		// handshake record, so no application-data record may have been
		// consumed, and we must not have sent any (tickets go out in
		// plaintext before the CipherSpec change).
		if framed.rxApp != 0 || framed.wLast != nil {
			return ReasonFraming
		}
	}

	return ""
}

// errFraming marks prepareKeys failures that stem from an unexpected
// handshake record layout rather than missing key material.
var errFraming = errors.New("ktls: unexpected handshake framing")

// prepareKeys computes the kernel crypto_info blobs for an offloadable
// connection and returns the TX record sequence the kernel continues with.
func (l *Listener) prepareKeys(state tls.ConnectionState, framed *framedConn, sniffer *keyLogSniffer, recoveredMaster []byte) (offloadKeys, uint64, error) {
	switch state.Version {
	case tls.VersionTLS13:
		txSecret, rxSecret, err := sniffer.secrets()
		if err != nil {
			return offloadKeys{}, 0, err
		}

		txSeq, err := computeTXSeq(framed.wLast, txSecret, state.CipherSuite)
		if err != nil {
			return offloadKeys{}, 0, fmt.Errorf("%w: %w", errFraming, err)
		}

		txInfo, err := buildCryptoInfo(txSecret, state.CipherSuite, txSeq)
		if err != nil {
			return offloadKeys{}, 0, err
		}

		// RX starts at sequence 0 by the framing invariant (see framedConn).
		rxInfo, err := buildCryptoInfo(rxSecret, state.CipherSuite, 0)
		if err != nil {
			return offloadKeys{}, 0, err
		}

		return offloadKeys{tx: txInfo, rx: rxInfo, txSecret: txSecret, rxSecret: rxSecret}, txSeq, nil

	case tls.VersionTLS12:
		params, ok := tls12CipherLookup[state.CipherSuite]
		if !ok {
			return offloadKeys{}, 0, fmt.Errorf("ktls: unsupported TLS 1.2 cipher suite 0x%04x", state.CipherSuite)
		}

		clientRandom, masterSecret, err := sniffer.masterSecret()
		if err != nil {
			// Resumed session: the sniffer is empty (CLIENT_RANDOM is logged
			// only on a full handshake), so use the master secret recovered from
			// the ticket plus the client random off the wire. verifyServerFinished
			// below still validates the derivation before the irreversible
			// offload. DidResume gates against a stale recoveredMaster from a
			// ticket whose resumption crypto/tls later declined.
			if !state.DidResume || len(recoveredMaster) == 0 {
				return offloadKeys{}, 0, err
			}

			// A missing client random is a secrets-capture failure like the empty
			// sniffer above, not framing: keep both as ReasonSecrets.
			wireClientRandom, haveClientRandom := framed.clientRandom()
			if !haveClientRandom {
				return offloadKeys{}, 0, errors.New("ktls: no ClientHello captured for resumed session")
			}

			masterSecret, clientRandom = recoveredMaster, wireClientRandom
		}

		serverRandom, ok := framed.serverRandom()
		if !ok {
			return offloadKeys{}, 0, fmt.Errorf("%w: no ServerHello captured", errFraming)
		}

		keyBlock, err := tls12KeyBlock(masterSecret, clientRandom, serverRandom, params)
		if err != nil {
			return offloadKeys{}, 0, err
		}

		// Confirm the derived server-write key against the real server
		// Finished before the irreversible offload: if it does not decrypt at
		// sequence 0, our key derivation or sequence model is wrong and we
		// fall back to userspace rather than ship a corrupt first record.
		// (Mirrors the TLS 1.3 trial decryption in computeTXSeq.)
		//
		// If the Finished was not captured at all (unexpected record layout, or
		// a body that overflowed the capture buffer) we cannot run this check,
		// so we fall back rather than offload unverified keys.
		finished, captured := framed.serverFinished()
		if !captured {
			return offloadKeys{}, 0, fmt.Errorf("%w: server Finished not captured for verification", errFraming)
		}
		if !verifyServerFinished(finished, keyBlock, params) {
			return offloadKeys{}, 0, fmt.Errorf("%w: server Finished did not verify", errFraming)
		}

		// Both directions sent exactly their Finished under the new keys
		// during the handshake, so both sequences continue at 1.
		const tls12Seq = 1

		return offloadKeys{
			tx: packCryptoInfo12(params, keyBlock, true, tls12Seq),
			rx: packCryptoInfo12(params, keyBlock, false, tls12Seq),
		}, tls12Seq, nil

	default:
		return offloadKeys{}, 0, fmt.Errorf("ktls: unexpected TLS version 0x%04x", state.Version)
	}
}

func (l *Listener) observe(reason string, remoteAddr net.Addr, state tls.ConnectionState, err error) {
	if l.observer != nil {
		l.observer(reason, remoteAddr, state, err)
	}
}
