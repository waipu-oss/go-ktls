//go:build integration

package ktls_integration

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestKTLSBadVersionRecordDoesNotHang reproduces the kTLS RX failure mode
// discussed in golang/go#44506: a TLS record with an invalid
// legacy_record_version, injected after the handshake, makes the kernel kTLS RX
// return EAGAIN from recvmsg, which can wedge a naive read loop until the peer
// disconnects. Our Read is a plain *net.TCPConn.Read (no RX splice), so it is
// bounded by net/http's ReadTimeout/IdleTimeout: the server must close the
// connection within its read timeout rather than hang or busy-spin.
//
// Run against a real server:
//
//	KTLS_TARGET=https://host:443/whatever \
//	  go test -tags integration -run BadVersion ./integration
//
// KTLS_BADVERSION_WAIT (default 30s) must comfortably exceed the server's
// ReadTimeout (for example 3s). The URL path is irrelevant; only host:port is used.
func TestKTLSBadVersionRecordDoesNotHang(t *testing.T) {
	addr := targetAddr(t)

	wait := 30 * time.Second
	if v := os.Getenv("KTLS_BADVERSION_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("KTLS_BADVERSION_WAIT: %v", err)
		}
		wait = d
	}

	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = raw.Close() }()

	// TLS 1.3 + http/1.1 only, so the server offloads to kTLS. (h2 stays in
	// userspace and would not exercise the kernel RX path.)
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // transport-level check against a dev/edge cert
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if st := tc.ConnectionState(); st.NegotiatedProtocol == "h2" {
		t.Skip("server negotiated h2 (userspace, no kTLS RX): cannot exercise this path")
	}

	// Inject a record with a deliberately invalid legacy_record_version
	// straight onto the raw socket, bypassing the client's TLS layer, so the
	// server's kernel kTLS RX meets a bad-version record as the next read.
	body := make([]byte, 32)
	rec := []byte{
		0x17,       // application_data
		0xff, 0xff, // invalid legacy_record_version
		byte(len(body) >> 8), byte(len(body)), // length
	}
	rec = append(rec, body...)
	if _, err := raw.Write(rec); err != nil {
		t.Fatalf("write bad-version record: %v", err)
	}

	// Drain anything still in flight (session tickets, a possible alert) and
	// wait for the close. A correct server closes within its read timeout, so
	// Read returns EOF/reset well before the deadline. A hang or busy-spin
	// leaves the connection open until our deadline fires -> failure.
	_ = raw.SetReadDeadline(time.Now().Add(wait))
	start := time.Now()

	buf := make([]byte, 4096)
	for {
		_, err = raw.Read(buf)
		if err != nil {
			break
		}
	}

	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatalf("server did not close within %s after a bad-version record "+
			"(hung or busy-spun on kTLS RX EAGAIN)", wait)
	default:
		t.Logf("server closed the connection after %s (err=%v): RX bad-version handled, no hang",
			time.Since(start).Round(time.Millisecond), err)
	}
}

// targetAddr extracts host:port from KTLS_TARGET (defaulting to :443).
func targetAddr(t *testing.T) string {
	t.Helper()

	raw := os.Getenv("KTLS_TARGET")
	if raw == "" {
		t.Skip("set KTLS_TARGET to the server's https URL to run")
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse KTLS_TARGET %q: %v", raw, err)
	}
	if u.Port() != "" {
		return u.Host
	}

	return net.JoinHostPort(u.Hostname(), "443")
}
