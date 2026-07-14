// Package ktls offloads TLS 1.3 and TLS 1.2 (AES-GCM) record encryption and
// decryption to the Linux kernel (kTLS) while keeping the handshake in
// userspace via crypto/tls.
//
// TLS 1.2 support exists primarily because mainline Linux gates TLS *device*
// offload (TLS_HW, NIC inline crypto) on TLS 1.2 AES-GCM: TLS 1.3 sessions
// always run as software kTLS. The TLS 1.2 path is simpler than 1.3: on a
// full handshake the key material comes from the CLIENT_RANDOM key log line
// plus the server random captured from our own outgoing ServerHello (RFC 5246
// key expansion). A resumed handshake logs no CLIENT_RANDOM, so there the
// master secret is recovered from our own session ticket: the listener owns
// WrapSession/UnwrapSession and stashes the master in the ticket's public Extra
// field at issue time, reading it back on resumption. The client random is read
// from the inbound ClientHello instead. Both record sequences are
// deterministically 1 after the handshake (each side's Finished is the only
// record sent under the new keys; session tickets go out in plaintext before the
// CipherSpec change). Before the irreversible offload, the derived server-write
// key is trial-decrypted against the captured server Finished record (mirroring
// the TLS 1.3 trial decryption in computeTXSeq), so any derivation error falls
// back to userspace cleanly instead of shipping a corrupt first record.
//
// Fork of github.com/Northernside/ktls (MIT License, Copyright (c) 2026
// Northernside) with substantial changes:
//
//   - Correct TX record sequence number: crypto/tls sends a NewSessionTicket
//     encrypted under the application traffic key during Handshake(), which the
//     upstream library did not account for (breaking every connection with
//     clients that offer psk_dhe_ke, i.e. all browsers). We trial-decrypt the
//     last record written during the handshake with the application traffic
//     key to determine how many records already consumed TX sequence numbers
//     (see computeTXSeq) and seed the kernel accordingly.
//   - Resumed TLS 1.2 sessions are offloaded, not only full handshakes: a
//     resumed handshake logs no CLIENT_RANDOM, so the listener owns session-
//     ticket issuance/redemption (WrapSession/UnwrapSession over a rotating key
//     ring), stashing the master secret in the ticket's public Extra field at
//     issue time and reading it back on resumption, with the client random taken
//     from the wire (see the TLS 1.2 note above). Gated so a caller's own ticket
//     scheme is never overridden.
//   - Record-boundary framing during the handshake: the wrapped connection
//     never reads past a TLS record boundary from the socket, so half-RTT
//     application data sent by the client stays in the kernel receive queue
//     and is picked up by kTLS RX. This removes the upstream drain logic and
//     its race (partially buffered ciphertext lost in tls.Conn.rawInput) and
//     makes the RX sequence number 0 by construction.
//   - RX offload is mandatory: with TX-only kTLS the receive path returns raw
//     ciphertext records, which cannot work for request/response protocols.
//     Offload is all-or-nothing; if it cannot be enabled cleanly the
//     connection falls back to userspace TLS.
//   - Each handshake runs in its own goroutine instead of serially inside
//     Accept, mirroring net/http's connection-per-goroutine model, so one
//     slow client cannot stall the accept loop.
//   - Connections that negotiate "h2" via ALPN (or TLS < 1.3) are returned as
//     real *tls.Conn so net/http's HTTP/2 path keeps working (net/http only
//     enables HTTP/2 for concrete *tls.Conn values).
//   - The offloaded connection implements io.ReaderFrom, delegating to the
//     underlying *net.TCPConn, so net/http can use sendfile(2) for file
//     responses (the kernel encrypts in place; this is the main perf win).
//   - close_notify alerts are sent through the kernel TLS control-message
//     interface on Close/CloseWrite.
//   - Reads use recvmsg with a TLS_GET_RECORD_TYPE cmsg buffer: the kernel
//     fails non-application-data records with EIO on a plain read(2), which
//     would turn a peer's clean close_notify into an I/O error. A peer
//     close_notify maps to io.EOF; other alerts surface as errors.
//   - Key updates (TLS 1.3): peer-initiated KeyUpdates are currently not
//     supported (keyUpdateSupported = false): each one costs HKDF
//     derivations plus setsockopt/sendmsg syscalls, which a peer interleaving
//     KeyUpdates with small application records could exploit as a CPU
//     amplification vector. Such connections are terminated cleanly; clients
//     in the wild virtually never send KeyUpdate mid-session and recover with
//     a fresh handshake. The full rekey flow (RFC 8446 section 4.6.3,
//     kernel >= 6.14) is implemented behind the flag.
//
// Requirements: Linux with the tls module loaded (modprobe tls). This package
// targets kernel >= 6.14, which covers every feature it uses (TLS
// 1.2/1.3 TX+RX, MSG_SPLICE_PAGES sendfile, TLS_TX_ZEROCOPY_RO,
// TLS_RX_EXPECT_NO_PAD, and key updates), so there is no version-gated
// fallback within the offload path. On other platforms (and if the tls
// module is absent) every connection transparently falls back to userspace
// TLS.
//
// On kernels older than 6.14 (e.g. 6.8) everything works except key updates,
// which need the rekey support added in 6.14: a second setsockopt(TLS_TX/RX)
// fails with EBUSY there and the kernel cannot switch the RX key, so the
// next peer record fails to decrypt (EBADMSG) and aborts the session.
// (With keyUpdateSupported = false a peer KeyUpdate closes the connection on
// every kernel regardless; see the KeyUpdate note above.)
//
// Known limitations:
//   - Configs returned from GetConfigForClient bypass the key log capture,
//     so those connections fall back to userspace TLS.
//   - Client-certificate configurations are not offloaded.
package ktls
