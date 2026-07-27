# go-ktls

[![Go Reference](https://pkg.go.dev/badge/github.com/waipu-oss/go-ktls.svg)](https://pkg.go.dev/github.com/waipu-oss/go-ktls)

Kernel TLS offload for a Go HTTPS listener.

The package hands TLS 1.3 and TLS 1.2 (AES-GCM) record encryption to the Linux
kernel (kTLS). The handshake stays in userspace via `crypto/tls`; afterwards the
negotiated keys go to the kernel with `setsockopt(SOL_TLS)` and reads and writes
no longer pass through the userspace TLS stack. That makes `sendfile(2)` usable
straight through the TLS socket, and on NICs with inline TLS offload
(ConnectX-6 Dx / ConnectX-7) file-backed plaintext pages can be DMAed directly
from the page cache to the NIC, which encrypts them on the wire. This avoids
per-byte encryption on the CPU and avoids writing the resulting ciphertext back
into host DRAM.

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
(`TLS_SW`), which still gives the sendfile and copy savings (see [Kernel
work](#kernel-work) for the series that would lift this). Verify with
`/proc/net/tls_stat` (`TlsTxSw` vs `TlsTxDevice`) and `ethtool -S <if> | grep -i tls`.

## Kernel work

kTLS series on netdev that affect this package. Status as of 2026-07-27, taken
from the `netdevbpf` project on patchwork.kernel.org; follow the threads for the
current state.

| Series | Why it matters here | Status |
| --- | --- | --- |
| [tls: Add TLS 1.3 hardware offload support](https://lore.kernel.org/netdev/20260709205325.1591196-1-rjethwani@purestorage.com/) (v15, 9 patches) | Would lift the TLS 1.2 restriction on NIC inline offload, so TLS 1.3 sessions could run as `TLS_HW` rather than `TLS_SW`, device KeyUpdate included. | changes requested; [v14](https://lore.kernel.org/netdev/20260515212715.3151307-1-rjethwani@purestorage.com/) superseded |
| [tls: device: push pending open record on splice EOF](https://lore.kernel.org/netdev/20260709224436.1608993-1-rjethwani@purestorage.com/) | Consumers relying on `ReadFrom` should know about this one: without it the kernel does not push a pending open record when the splice ends. Go issues `sendfile(2)` unbounded, so it is easy to reach. | in mainline since `v7.2-rc5`, commit `eaa39f9f8ac8` |
| [net/mlx5e: fix NULL derefs when RX queue mapping outlives channel reconfig](https://lore.kernel.org/netdev/20260714222915.2334949-1-rjethwani@purestorage.com/) (2 patches) | Only with mlx5 inline offload: NULL dereferences when an RX queue mapping survives a channel reconfiguration. | awaiting upstream |
| [net/mlx5e: ktls: guard RX resync against missing TLS context](https://lore.kernel.org/netdev/20260717224646.2782929-1-rjethwani@purestorage.com/) | Same path as above: RX resync running with no TLS context attached. | awaiting upstream |

## Limitations

These connections are not broken. They are served through userspace TLS exactly
as without this package. The `result` label says which bucket a connection hit.

| Limitation | `result` |
| --- | --- |
| TLS 1.1 and below never offloaded. TLS 1.2 offloaded for the six AES-GCM suites only (CBC and ChaCha20 fall back). TLS 1.3 offloads all three suites; ChaCha20 as software kTLS only. | `tls-version` / `cipher` |
| HTTP/2 (ALPN `h2`): net/http enables h2 only for concrete `*tls.Conn`, so those stay in userspace. | `alpn` |
| Client certificates (`ClientAuth != NoClientCert`) are not offloaded. | `client-auth` |
| `GetConfigForClient` returning a non-nil config bypasses the key capture. | `secrets` |
| TLS 1.3 without a session ticket: the kernel TX sequence is derived from the `NewSessionTicket` record, so a connection that gets none is not offloaded. Applies to `SessionTicketsDisabled` and to clients that do not offer `psk_dhe_ke` (browsers and curl do; a Go client only with a `ClientSessionCache`). | `framing` |
| Peer-initiated TLS 1.3 key updates are rejected (CPU-amplification guard; the rekey machinery exists behind a flag). | conn closed |
| TLS 1.2 renegotiation and 0-RTT / early data are not supported. | conn closed / n/a |
| Half-offload failure (TX up, later step fails): the socket cannot return to userspace and is closed. | `conn-unusable` |

The offloaded connection is not a `*tls.Conn`. Use `ConnectionState()` (net/http
populates `Request.TLS` through it) and `NetConn()` (unwrap to `*net.TCPConn`).

## Performance

Steady-state data transfer adds no userspace overhead: offloaded connections
read and write the raw `*net.TCPConn`, and `ReadFrom` delegates to it for
sendfile. The per-connection offload setup runs once at handshake time.

### In production

Live video edge (DASH, HLS) on AMD EPYC Zen2, ConnectX-6 Dx 2x100G, kernel 7.2
netdev tree with the TLS 1.3 device offload series applied, TX on the device path
(RX was enabled during v14 testing):

- 130 Gbit/s egress, ~99.5% of eligible TX traffic HW-offloaded
- ~19k concurrent streams, 85% TLS 1.3, 15% TLS 1.2
- DRAM bytes per egress byte: 5.4x without kTLS, 2.2x with

On this workload the main win is not the AES offload but avoiding the ciphertext
write back into DRAM. Mainline currently only exposes device offload for the
TLS 1.2 AES-GCM path; TLS 1.3 needs [this series](#kernel-work).

### What it does not fix

Removing the encrypt-and-copy path reduces memory traffic and CPU/cache pressure.
It does not shrink the per-connection kernel state, so the ceiling set by L3
capacity versus connection count is unchanged. Two separate effects: per-byte
memory traffic, which kTLS moves, and per-connection state locality, which kTLS
does not.

### Microbenchmarks

Apple M2 Max, loopback, `go test -bench .`. Handshake and record framer only;
the offload is Linux-only and is not exercised here:

```
BenchmarkHandshake/ktls/full     667µs/op   (vs 707µs baseline crypto/tls; ECDHE dominates)
BenchmarkHandshake/ktls/resumed  570µs/op   (vs 474µs; ~0.1ms per-handshake goroutine hop)
BenchmarkFramerRead              54-57 GB/s, 0 allocs
BenchmarkBuildCryptoInfo         0.8µs      (x2 per conn: TX and RX)
```
