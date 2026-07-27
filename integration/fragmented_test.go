//go:build integration

package ktls_integration

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// chunkWriteConn splits every Write into tiny segments, so the bytes the client
// sends (ClientHello and the rest of the handshake flight, then the request)
// arrive at the server in adversarial TCP chunks. This exercises the listener's
// record framer end-to-end against a real kernel: it must keep reading at record
// boundaries no matter how the stream is segmented, complete the handshake,
// offload, and serve uncorrupted bytes.
type chunkWriteConn struct {
	net.Conn

	rnd *rand.Rand
	max int
}

func (c *chunkWriteConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := 1 + c.rnd.IntN(c.max)
		if n > len(b) {
			n = len(b)
		}
		w, err := c.Conn.Write(b[:n])
		total += w
		if err != nil {
			return total, err
		}
		b = b[n:]
	}

	return total, nil
}

// TestKTLSFragmentedDelivery is a differential check: the body served over a
// connection whose client bytes are fragmented into tiny TCP segments must be
// byte-identical to the body served over a normal connection. A framing or
// offload bug under fragmentation corrupts or truncates the response, so the
// hash diverges. Requires KTLS_TARGET to be a URL that returns 200 with a
// stable body, like the matrix test.
func TestKTLSFragmentedDelivery(t *testing.T) {
	u := targetURL(t)

	ref, err := fetch(u, 0) // 0 = no fragmentation (reference)
	if err != nil {
		t.Fatalf("reference fetch: %v", err)
	}
	if ref.status != http.StatusOK {
		t.Fatalf("reference status %d (want 200): point KTLS_TARGET at a cacheable 200 URL", ref.status)
	}
	t.Logf("reference: %d bytes, sha256=%s, tls=%#x", ref.n, ref.hash[:16], ref.version)

	for _, maxChunk := range []int{1, 2, 5, 17} {
		for seed := range uint64(5) {
			got, err := fetch(u, maxChunk, seed)
			if err != nil {
				t.Fatalf("maxChunk=%d seed=%d: %v", maxChunk, seed, err)
			}
			if got.status != ref.status {
				t.Fatalf("maxChunk=%d seed=%d: status %d, want %d", maxChunk, seed, got.status, ref.status)
			}
			if got.hash != ref.hash {
				t.Fatalf("maxChunk=%d seed=%d: body sha256 %s != reference %s (offload corrupted %d vs %d bytes)",
					maxChunk, seed, got.hash[:16], ref.hash[:16], got.n, ref.n)
			}
		}
	}
	t.Logf("ok: identical body across fragmented deliveries (maxChunk 1..17, 5 seeds each)")
}

type result struct {
	status  int
	n       int
	hash    string
	version uint16
}

// fetch does one HTTP/1.1 GET over a fresh TLS 1.3 (http/1.1) connection. When
// maxChunk > 0, client writes are fragmented into 1..maxChunk-byte TCP segments.
func fetch(u *url.URL, maxChunk int, seed ...uint64) (result, error) {
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}

	raw, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return result{}, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))

	under := raw
	if maxChunk > 0 {
		s := uint64(1)
		if len(seed) > 0 {
			s = seed[0] + 1
		}
		under = &chunkWriteConn{Conn: raw, rnd: rand.New(rand.NewPCG(s, uint64(maxChunk))), max: maxChunk}
	}

	tc := tls.Client(under, &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true, //nolint:gosec // transport correctness check; the cert may be self-signed
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		return result{}, fmt.Errorf("handshake: %w", err)
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: ktls-frag-test\r\n\r\n",
		u.RequestURI(), u.Host)
	if _, err := tc.Write([]byte(req)); err != nil {
		return result{}, fmt.Errorf("write request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		return result{}, fmt.Errorf("read response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result{}, fmt.Errorf("read body: %w", err)
	}

	return result{
		status:  resp.StatusCode,
		n:       len(body),
		hash:    fmt.Sprintf("%x", sha256.Sum256(body)),
		version: tc.ConnectionState().Version,
	}, nil
}

// targetURL parses KTLS_TARGET into a URL (skips if unset).
func targetURL(t *testing.T) *url.URL {
	t.Helper()

	raw := os.Getenv("KTLS_TARGET")
	if raw == "" {
		t.Skip("set KTLS_TARGET to an https URL serving a stable response body to run")
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse KTLS_TARGET %q: %v", raw, err)
	}

	return u
}
