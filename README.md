# go-ktls

[![CI](https://github.com/waipu-oss/go-ktls/actions/workflows/ci.yml/badge.svg)](https://github.com/waipu-oss/go-ktls/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/waipu-oss/go-ktls.svg)](https://pkg.go.dev/github.com/waipu-oss/go-ktls)
[![Go Report Card](https://goreportcard.com/badge/github.com/waipu-oss/go-ktls)](https://goreportcard.com/report/github.com/waipu-oss/go-ktls)

Kernel TLS offload for a Go HTTPS listener.

The package hands TLS 1.3 and TLS 1.2 (AES-GCM) record encryption to the Linux
kernel (kTLS). The handshake stays in userspace via `crypto/tls`; afterwards the
negotiated keys go to the kernel with `setsockopt(SOL_TLS)` and reads and writes
no longer pass through the userspace TLS stack. That makes `sendfile(2)` usable
straight through the TLS socket, and on NICs with inline TLS offload
(ConnectX-6 Dx / ConnectX-7) it keeps the plaintext off the CPU entirely: page
cache to DMA, with the NIC encrypting on the wire.

It is a fork of [Northernside/ktls](https://github.com/Northernside/ktls) (MIT)
with substantial correctness and architecture changes; see [doc.go](doc.go) for
the full rationale and the design of each path.

## Install

```sh
go get github.com/waipu-oss/go-ktls
```

Requires Go 1.25. Builds everywhere; the offload itself is Linux-only.

## Usage

```go
ln, _ := net.Listen("tcp", ":443")
srv.Serve(ktls.NewListener(ln, tlsConfig,
    ktls.WithObserver(func(reason string, remoteAddr net.Addr, state tls.ConnectionState, err error) {
        // reason is "offloaded" on success, otherwise a fallback bucket
    }),
))
```

Any connection that cannot be offloaded falls back to userspace TLS (a plain
`*tls.Conn`) transparently, so enabling kTLS is safe even where the kernel does
not support it. The observer reports which bucket each connection landed in.

## Requirements

Targets kernel 6.14 or newer, which covers every kTLS feature used, so the
offload path carries no kernel-version fallbacks. On other platforms, or without
the `tls` module (`modprobe tls`), everything falls back to userspace TLS;
`Available()` reports kernel support.

NIC inline offload (`TLS_HW`) additionally needs `CONFIG_TLS_DEVICE=y`, a
supported NIC and firmware, and `ethtool -K <if> tls-hw-tx-offload on`. Mainline
Linux gates it on TLS 1.2 AES-GCM; TLS 1.3 always runs as software kTLS
(`TLS_SW`), which still gives the sendfile and copy savings. Verify with
`/proc/net/tls_stat` (`TlsTxSw` vs `TlsTxDevice`) and `ethtool -S <if> | grep -i tls`.

## Limitations

These connections are not broken. They are served through userspace TLS exactly
as without this package. The `result` label says which bucket a connection hit.

| Limitation | `result` |
| --- | --- |
| TLS 1.1 and below never offloaded. TLS 1.2 offloaded for the six AES-GCM suites only (CBC and ChaCha20 fall back). TLS 1.3 offloads all three suites; ChaCha20 as software kTLS only. | `tls-version` / `cipher` |
| HTTP/2 (ALPN `h2`): net/http enables h2 only for concrete `*tls.Conn`, so those stay in userspace. | `alpn` |
| Client certificates (`ClientAuth != NoClientCert`) are not offloaded. | `client-auth` |
| `GetConfigForClient` returning a non-nil config bypasses the key capture. | `secrets` |
| Peer-initiated TLS 1.3 key updates are rejected (CPU-amplification guard; the rekey machinery exists behind a flag). | conn closed |
| TLS 1.2 renegotiation and 0-RTT / early data are not supported. | conn closed / n/a |
| Half-offload failure (TX up, later step fails): the socket cannot return to userspace and is closed. | `conn-unusable` |

The offloaded connection is not a `*tls.Conn`. Use `ConnectionState()` (net/http
populates `Request.TLS` through it) and `NetConn()` (unwrap to `*net.TCPConn`).

## Performance

Steady-state data transfer adds no userspace overhead: offloaded connections
read and write the raw `*net.TCPConn`, and `ReadFrom` delegates to it for
sendfile. The per-connection offload setup runs once at handshake time.
Microbenchmarks (Apple M2 Max, loopback, `go test -bench .`):

```
BenchmarkHandshake/ktls/full     667µs/op   (vs 707µs baseline crypto/tls; ECDHE dominates)
BenchmarkHandshake/ktls/resumed  570µs/op   (vs 474µs; ~0.1ms per-handshake goroutine hop)
BenchmarkFramerRead              54-57 GB/s, 0 allocs
BenchmarkBuildCryptoInfo         0.8µs      (x2 per conn: TX and RX)
```
