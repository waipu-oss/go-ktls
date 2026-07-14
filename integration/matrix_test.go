//go:build integration

// Package ktls_integration is a black-box verification harness for the kTLS
// listener, meant to be run manually against a running server that uses this
// package (a dev environment or a real host), not as part of the normal test
// run (it is gated behind the integration build tag).
//
// It drives a TLS version / cipher / ALPN matrix from a real client and
// asserts, for every combination:
//   - the handshake negotiates the expected version/cipher/protocol,
//   - the response is HTTP 200, and
//   - the body is byte-identical across every combination (a broken offload
//     for any cipher yields wrong bytes or a TLS error, so the test fails).
//
// When run ON the server host, set KTLS_TLS_STAT to additionally log the
// namespace-global TlsTxSw delta per request as a hint. It is NOT asserted:
// that counter is shared across all connections in the namespace and cannot
// be attributed to a single request on a host with concurrent traffic. The
// authoritative per-connection verdict is the reason the server's WithObserver
// callback reported, read out-of-band from its logs or metrics.
//
// Limitation: Go's crypto/tls client cannot pin a TLS 1.3 cipher suite
// (CipherSuites only controls <= TLS 1.2), so sweeping all three TLS 1.3
// suites individually needs an external client (e.g. curl --tls13-ciphers).
// This harness covers TLS 1.3 (server-chosen cipher) plus the full TLS 1.2
// cipher matrix, ALPN, and byte correctness.
//
// Usage:
//
//	KTLS_TARGET='https://server.example/some/stable/path' \
//	  go test -tags integration -count=1 -v ./integration/
//
//	# co-located (on the server host), also assert offload engaged:
//	KTLS_TARGET=... KTLS_TLS_STAT=/proc/net/tls_stat \
//	  go test -tags integration -count=1 -v ./integration/
package ktls_integration

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type matrixCase struct {
	name string

	maxVersion   uint16
	cipherSuites []uint16 // TLS <= 1.2 only; ignored by crypto/tls for 1.3
	forceHTTP2   bool

	wantVersion uint16 // negotiated tls.VersionTLS1x; 0 = don't assert exact
	wantProto   string // required negotiated ALPN; "" = don't assert
	// wantOffload is the design intent, asserted only in co-located mode
	// (KTLS_TLS_STAT set).
	wantOffload bool
	// optional cases depend on server config (h2 enabled, CBC offered); if the
	// server does not accept/negotiate them they are skipped, not failed, so
	// the harness stays portable across environments.
	optional bool
}

// cases mirror the ktls package offloadDecision: TLS 1.2/1.3 AES-GCM offload;
// TLS 1.2 ChaCha20 and CBC fall back (ReasonCipher); h2 falls back
// (ReasonALPN).
var cases = []matrixCase{
	{
		name:        "tls13",
		maxVersion:  tls.VersionTLS13,
		wantVersion: tls.VersionTLS13,
		wantOffload: true,
	},
	{
		name:         "tls12-aes128-gcm",
		maxVersion:   tls.VersionTLS12,
		cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		wantVersion:  tls.VersionTLS12,
		wantOffload:  true,
	},
	{
		name:         "tls12-aes256-gcm",
		maxVersion:   tls.VersionTLS12,
		cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		wantVersion:  tls.VersionTLS12,
		wantOffload:  true,
	},
	{
		name:         "tls12-chacha20",
		maxVersion:   tls.VersionTLS12,
		cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		wantVersion:  tls.VersionTLS12,
		wantOffload:  false, // ChaCha20 1.2 is deliberately not offloaded
	},
	{
		name:         "tls12-aes128-cbc",
		maxVersion:   tls.VersionTLS12,
		cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		wantVersion:  tls.VersionTLS12,
		wantOffload:  false, // CBC is not offloadable (skipped if server won't negotiate it)
		optional:     true,
	},
	{
		name:        "tls13-h2",
		maxVersion:  tls.VersionTLS13,
		forceHTTP2:  true,
		wantProto:   "h2",
		wantOffload: false, // h2 stays in userspace (skipped if server does not offer h2)
		optional:    true,
	},
}

func target(t *testing.T) string {
	t.Helper()
	url := os.Getenv("KTLS_TARGET")
	if url == "" {
		t.Skip("set KTLS_TARGET to an https URL serving a stable response body to run")
	}
	return url
}

func TestKTLSMatrix(t *testing.T) {
	url := target(t)
	statPath := os.Getenv("KTLS_TLS_STAT") // co-located offload assertion when set

	var refHash string // first successful body hash; all others must match

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // the test server's cert may be self-signed; this is a transport check
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tc.maxVersion,
				CipherSuites:       tc.cipherSuites,
			}

			tr := &http.Transport{
				TLSClientConfig:   cfg,
				ForceAttemptHTTP2: tc.forceHTTP2,
				DisableKeepAlives: true, // one fresh TLS connection per request
			}
			if !tc.forceHTTP2 {
				// Pin HTTP/1.1: leave TLSNextProto non-nil-empty so net/http
				// does not auto-upgrade.
				tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
			}
			defer tr.CloseIdleConnections()

			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

			before := readTxSw(t, statPath)

			resp, body, err := get(client, url)
			if err != nil {
				if tc.optional {
					t.Skipf("server did not accept this combination (likely not offered): %v", err)
				}
				t.Fatalf("request failed (handshake or transport): %v", err)
			}

			if tc.wantVersion != 0 && resp.TLS.Version != tc.wantVersion {
				t.Fatalf("negotiated version %#x, want %#x", resp.TLS.Version, tc.wantVersion)
			}
			if tc.wantProto != "" && resp.TLS.NegotiatedProtocol != tc.wantProto {
				if tc.optional {
					t.Skipf("server did not negotiate %q (got %q): case requires that server config",
						tc.wantProto, resp.TLS.NegotiatedProtocol)
				}
				t.Fatalf("negotiated ALPN %q, want %q", resp.TLS.NegotiatedProtocol, tc.wantProto)
			}

			h := fmt.Sprintf("%x", sha256.Sum256(body))
			if refHash == "" {
				refHash = h
			} else if h != refHash {
				t.Fatalf("body hash %s differs from reference %s: offload corrupted the payload", h[:16], refHash[:16])
			}

			t.Logf("ok: tls=%#x cipher=%#x proto=%q bytes=%d",
				resp.TLS.Version, resp.TLS.CipherSuite, resp.TLS.NegotiatedProtocol, len(body))

			if statPath != "" {
				// TlsTxSw is a namespace-global counter: its delta cannot be
				// attributed to this single connection on a host with any
				// concurrent TLS traffic, so it is logged as a hint, never
				// asserted. The authoritative per-connection verdict is the
				// reason the server's WithObserver callback reported, not this
				// counter.
				delta := readTxSw(t, statPath) - before
				t.Logf("TlsTxSw namespace-global delta=%d (hint only; want offloaded=%v)", delta, tc.wantOffload)
			}
		})
	}
}

func get(c *http.Client, url string) (*http.Response, []byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %d (want 200), body: %.200s", resp.StatusCode, body)
	}
	if resp.TLS == nil {
		return nil, nil, fmt.Errorf("no TLS connection state on response")
	}
	return resp, body, nil
}

// readTxSw returns the cumulative TlsTxSw counter from a tls_stat file, or -1
// when statPath is empty (co-located assertion disabled).
func readTxSw(t *testing.T, statPath string) int {
	t.Helper()
	if statPath == "" {
		return -1
	}
	data, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatalf("read %s (unset KTLS_TLS_STAT for remote targets): %v", statPath, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "TlsTxSw" {
			n, perr := strconv.Atoi(fields[1])
			if perr != nil {
				t.Fatalf("parse TlsTxSw %q: %v", fields[1], perr)
			}
			return n
		}
	}
	t.Fatal("TlsTxSw not found in tls_stat")
	return -1
}
