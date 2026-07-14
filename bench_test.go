package ktls

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// BenchmarkHandshake measures the full per-connection setup cost from the
// client's perspective: TCP connect, TLS 1.3 handshake, ticket delivery,
// close. The ktls variants additionally run record framing, key log capture,
// secret parsing and the TX-sequence trial decryption (on Linux with kernel
// support also the setsockopt offload): the delta against the tls baseline
// is the per-connection overhead of this package.
func BenchmarkHandshake(b *testing.B) {
	for _, bench := range []struct {
		name    string
		useKTLS bool
		resume  bool
	}{
		{"tls/full", false, false},
		{"ktls/full", true, false},
		{"tls/resumed", false, true},
		{"ktls/resumed", true, true},
	} {
		b.Run(bench.name, func(b *testing.B) {
			benchmarkHandshake(b, bench.useKTLS, bench.resume)
		})
	}
}

func benchmarkHandshake(b *testing.B, useKTLS, resume bool) {
	b.Helper()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(b)}, MinVersion: tls.VersionTLS13}

	var ln net.Listener
	if useKTLS {
		ln = NewListener(inner, cfg)
	} else {
		ln = tls.NewListener(inner, cfg)
	}
	b.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}

			go func(c net.Conn) {
				// tls.NewListener hands out unhandshaked conns; drive the
				// handshake explicitly so both variants do equal work.
				if hs, ok := c.(interface{ Handshake() error }); ok {
					_ = hs.Handshake()
				}
				_ = c.Close()
			}(c)
		}
	}()

	dial := func(cache tls.ClientSessionCache) {
		b.Helper()

		conn, derr := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			ClientSessionCache: cache,
		})
		if derr != nil {
			b.Fatal(derr)
		}

		// Read until the server closes: this delivers the session ticket
		// (required for the resumed variants) and synchronizes iterations.
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}

	cache := tls.NewLRUClientSessionCache(8)
	if resume {
		dial(cache) // warm the session cache
	}

	b.ReportAllocs()

	for b.Loop() {
		if resume {
			dial(cache)
		} else {
			dial(tls.NewLRUClientSessionCache(1))
		}
	}
}

// BenchmarkFramerRead measures steady-state read throughput through the
// framedConn. "framed" is the capped-read mode active during the handshake;
// "released" is the passthrough mode every userspace-TLS fallback connection
// (TLS 1.2, h2, no kernel support) uses for its entire lifetime; "raw" is the
// baseline without the wrapper.
func BenchmarkFramerRead(b *testing.B) {
	var recs []byte
	for range 64 {
		recs = append(recs, record(recordTypeApplicationData, 16384)...)
	}

	for _, mode := range []string{"framed", "released", "raw"} {
		b.Run(mode, func(b *testing.B) {
			src := &replayConn{data: recs}
			var conn net.Conn = src

			if mode != "raw" {
				f := &framedConn{Conn: src}
				if mode == "released" {
					f.release()
				}
				conn = f
			}

			buf := make([]byte, 32*1024)

			b.ReportAllocs()
			b.SetBytes(int64(len(recs)))

			for b.Loop() {
				src.pos = 0
				for {
					_, err := conn.Read(buf)
					if err == io.EOF {
						break
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// BenchmarkFramerWrite measures the write-side record capture active during
// the handshake (the path crypto/tls flushes its flights through).
func BenchmarkFramerWrite(b *testing.B) {
	flight := append(record(recordTypeHandshake, 2048), record(recordTypeApplicationData, 4096)...)
	flight = append(flight, record(recordTypeApplicationData, 245)...)

	for _, mode := range []string{"capture", "released"} {
		b.Run(mode, func(b *testing.B) {
			f := &framedConn{Conn: nopConn{}}
			if mode == "released" {
				f.release()
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(flight)))

			for b.Loop() {
				if _, err := f.Write(flight); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkComputeTXSeq measures the once-per-connection trial decryption:
// the ticket case (opens on the first sequence) and the fallback case (opens
// at no sequence, the worst case of two failed AEAD opens).
func BenchmarkComputeTXSeq(b *testing.B) {
	const suite = uint16(0x1301)

	secret := testSecret(32)
	ticket := sealRecord(b, secret, suite, 0, make([]byte, 245))
	unexpected := record(recordTypeApplicationData, 53) // opens at no sequence, forces fallback

	for _, bench := range []struct {
		name    string
		rec     []byte
		wantErr bool
		expect  uint64
	}{
		{"ticket", ticket, false, 1},
		{"fallback", unexpected, true, 0},
	} {
		b.Run(bench.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				seq, err := computeTXSeq(bench.rec, secret, suite)
				if bench.wantErr {
					if err == nil {
						b.Fatal("expected fallback error")
					}

					continue
				}
				if err != nil {
					b.Fatal(err)
				}
				if seq != bench.expect {
					b.Fatalf("unexpected sequence %d", seq)
				}
			}
		})
	}
}

// BenchmarkKeyLogSecrets measures key log capture and secret extraction,
// once per connection.
func BenchmarkKeyLogSecrets(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		sniffer := &keyLogSniffer{}
		if _, err := sniffer.Write([]byte(testKeyLog)); err != nil {
			b.Fatal(err)
		}
		if _, _, err := sniffer.secrets(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBuildCryptoInfo measures the HKDF key/IV derivation and kernel
// struct packing, twice per connection (TX and RX).
func BenchmarkBuildCryptoInfo(b *testing.B) {
	secret := testSecret(32)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := buildCryptoInfo(secret, 0x1301, 1); err != nil {
			b.Fatal(err)
		}
	}
}

// replayConn serves a fixed byte stream, resettable via pos.
type replayConn struct {
	nopConn

	data []byte
	pos  int
}

func (r *replayConn) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	n := copy(p, r.data[r.pos:])
	r.pos += n

	return n, nil
}

// sealRecord encrypts payload as a TLS 1.3 application-data record at the given
// sequence number, like crypto/tls (and later the kernel) does.
func sealRecord(tb testing.TB, secret []byte, suite uint16, seq uint64, payload []byte) []byte {
	tb.Helper()

	key, iv, err := trafficKeyIV(secret, cipherLookup[suite])
	if err != nil {
		tb.Fatal(err)
	}

	aead, err := aeadForSuite(suite, key)
	if err != nil {
		tb.Fatal(err)
	}

	inner := append(payload, recordTypeHandshake) // inner content type
	bodyLen := len(inner) + aead.Overhead()

	rec := make([]byte, recordHeaderLen, recordHeaderLen+bodyLen)
	rec[0] = recordTypeApplicationData
	rec[1], rec[2] = 3, 3
	binary.BigEndian.PutUint16(rec[3:], uint16(bodyLen)) //nolint:gosec // bounded test payload

	nonce := make([]byte, len(iv))
	recordNonce(nonce, iv, seq)

	return aead.Seal(rec, nonce, inner, rec[:recordHeaderLen])
}
