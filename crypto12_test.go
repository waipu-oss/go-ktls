package ktls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refTLS12PRF is an independent P_hash implementation (RFC 5246 section 5)
// used to cross-check tls12PRF; the end-to-end validation against crypto/tls
// happens in TestTLS12FinishedRecordDecrypt.
func refTLS12PRF(secret []byte, label string, seed []byte, length int, h func() hash.Hash) []byte {
	labelSeed := append([]byte(label), seed...)

	hm := func(parts ...[]byte) []byte {
		mac := hmac.New(h, secret)
		for _, p := range parts {
			mac.Write(p)
		}

		return mac.Sum(nil)
	}

	// Precompute A(1..n) first, then the output blocks.
	var as [][]byte
	a := labelSeed
	for total := 0; total < length; total += h().Size() {
		a = hm(a)
		as = append(as, a)
	}

	var out []byte
	for _, ai := range as {
		out = append(out, hm(ai, labelSeed)...)
	}

	return out[:length]
}

func TestTLS12PRFMatchesReference(t *testing.T) {
	secret := testSecret(48)
	seed := testSecret(64)

	for _, h := range []func() hash.Hash{sha256.New, sha512.New384} {
		for _, length := range []int{1, 12, 40, 72, 100} {
			got := tls12PRF(secret, "key expansion", seed, length, h)
			assert.Equal(t, refTLS12PRF(secret, "key expansion", seed, length, h), got,
				"hash size %d length %d", h().Size(), length)
		}
	}
}

func TestPackCryptoInfo12Layout(t *testing.T) {
	master := testSecret(48)
	clientRandom := testSecret(32)
	serverRandom := append(testSecret(31), 0xff)

	for suiteID, params := range tls12CipherLookup {
		// Derive the key block the production way, then (below) slice out the
		// per-direction key and salt with a manual offset formula instead of
		// writeKeyIV, so the assertions cross-check the split rather than
		// mirror it.
		keyBlock, err := tls12KeyBlock(master, clientRandom, serverRandom, params)
		require.NoError(t, err)

		const recSeq = uint64(0x0102030405060708)

		for _, serverWrite := range []bool{true, false} {
			info := packCryptoInfo12(params, keyBlock, serverWrite, recSeq)
			require.Len(t, info, params.infoSize(), "suite 0x%04x", suiteID)

			// key_block = client_write_key | server_write_key | client_IV | server_IV.
			keyStart, saltStart := 0, 2*params.keyLen
			if serverWrite {
				keyStart, saltStart = params.keyLen, 2*params.keyLen+tls12SaltLen
			}
			wantKey := keyBlock[keyStart : keyStart+params.keyLen]
			wantSalt := keyBlock[saltStart : saltStart+tls12SaltLen]

			off := 0
			assert.Equal(t, uint16(kernelTLS12), binary.LittleEndian.Uint16(info[off:]))
			off += 2
			assert.Equal(t, params.kernelCipher, binary.LittleEndian.Uint16(info[off:]))
			off += 2
			assert.Equal(t, recSeq, binary.BigEndian.Uint64(info[off:]), "explicit nonce seed")
			off += tls12IVLen
			assert.Equal(t, wantKey, info[off:off+params.keyLen], "suite 0x%04x serverWrite=%v key", suiteID, serverWrite)
			off += params.keyLen
			assert.Equal(t, wantSalt, info[off:off+tls12SaltLen], "fixed IV")
			off += tls12SaltLen
			assert.Equal(t, recSeq, binary.BigEndian.Uint64(info[off:]), "rec_seq")
		}
	}
}

func TestTLS12KeyBlockRejectsShortMaterial(t *testing.T) {
	params := tls12CipherLookup[tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]

	_, err := tls12KeyBlock(testSecret(47), testSecret(32), testSecret(32), params) // short master
	require.Error(t, err)

	_, err = tls12KeyBlock(testSecret(48), testSecret(31), testSecret(32), params) // short client random
	require.Error(t, err)
}

func TestVerifyServerFinishedRejectsWrongKeys(t *testing.T) {
	params := tls12CipherLookup[tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]

	keyBlock, err := tls12KeyBlock(testSecret(48), testSecret(32), testSecret(32), params)
	require.NoError(t, err)

	// Random bytes are not a valid GCM record under the derived key.
	body := make([]byte, tls12IVLen+24)
	for i := range body {
		body[i] = byte(i)
	}
	assert.False(t, verifyServerFinished(body, keyBlock, params),
		"garbage must not verify: guards the irreversible offload against derivation errors")

	assert.False(t, verifyServerFinished(body[:tls12IVLen+1], keyBlock, params),
		"a body shorter than nonce+tag must not verify")
}

func TestServerFinishedCapture(t *testing.T) {
	f := &framedConn{Conn: nopConn{}}

	mustWrite := func(b []byte) {
		t.Helper()
		_, err := f.Write(b)
		require.NoError(t, err)
	}

	// ServerHello, Certificate, ServerHelloDone (handshake), then CCS, then the
	// encrypted Finished, the real TLS 1.2 server flight order.
	mustWrite(append([]byte{recordTypeHandshake, 3, 3, 0, 42}, make([]byte, 42)...))
	_, ok := f.serverFinished()
	assert.False(t, ok, "no Finished before the ChangeCipherSpec")

	mustWrite([]byte{recordTypeChangeCipherSpec, 3, 3, 0, 1, 1})

	finishedBody := make([]byte, 40)
	for i := range finishedBody {
		finishedBody[i] = byte(i + 1)
	}
	mustWrite(append([]byte{recordTypeHandshake, 3, 3, 0, byte(len(finishedBody))}, finishedBody...))

	got, ok := f.serverFinished()
	require.True(t, ok)
	assert.Equal(t, finishedBody, got)
}

// TestPrepareKeysTLS12FailsClosedWithoutFinished pins the fail-closed
// behaviour: when the server Finished was not captured, prepareKeys must
// refuse to offload (returning errFraming, which routes the connection to the
// userspace TLS fallback) rather than install unverified keys for the
// irreversible offload.
func TestPrepareKeysTLS12FailsClosedWithoutFinished(t *testing.T) {
	l := &Listener{}
	state := tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	// framedConn that captured the ServerHello (so serverRandom succeeds) and
	// saw the ChangeCipherSpec, but never captured a server Finished record.
	framed := &framedConn{Conn: nopConn{}}
	helloBody := append([]byte{2, 0, 0, 70, 3, 3}, testSecret(32)...) // ServerHello: type, length, version, random
	_, err := framed.Write(append([]byte{recordTypeHandshake, 3, 3, byte(len(helloBody) >> 8), byte(len(helloBody))}, helloBody...))
	require.NoError(t, err)
	_, err = framed.Write([]byte{recordTypeChangeCipherSpec, 3, 3, 0, 1, 1})
	require.NoError(t, err)

	if _, captured := framed.serverFinished(); captured {
		t.Fatal("test precondition: server Finished must not be captured")
	}

	// Sniffer with a valid CLIENT_RANDOM master-secret line so the derivation
	// reaches the Finished verification step.
	sniffer := &keyLogSniffer{}
	line := fmt.Sprintf("%s %s %s\n", labelClientRandom,
		hex.EncodeToString(testSecret(32)), hex.EncodeToString(testSecret(48)))
	_, err = sniffer.Write([]byte(line))
	require.NoError(t, err)

	_, _, err = l.prepareKeys(state, framed, sniffer, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errFraming,
		"an uncaptured server Finished must fall back to userspace, not offload unverified keys")
}

func TestServerRandomCapture(t *testing.T) {
	random := testSecret(32)

	// ServerHello: HandshakeType(2) + length(3) + version(2) + random(32) + trailing fields.
	body := append([]byte{2, 0, 0, 70, 3, 3}, random...)
	body = append(body, make([]byte, 38)...)
	rec := append([]byte{recordTypeHandshake, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)

	f := &framedConn{Conn: nopConn{}}

	// Written in odd chunks, like a buffered flight flush would arrive.
	for off := 0; off < len(rec); off += 3 {
		_, err := f.Write(rec[off:min(off+3, len(rec))])
		require.NoError(t, err)
	}

	got, ok := f.serverRandom()
	require.True(t, ok)
	assert.Equal(t, random, got)

	// A second handshake record (e.g. Certificate) must not overwrite it.
	other := record(recordTypeHandshake, 100)
	_, err := f.Write(other)
	require.NoError(t, err)

	got, ok = f.serverRandom()
	require.True(t, ok)
	assert.Equal(t, random, got)
}

func TestServerRandomCaptureRejectsNonServerHello(t *testing.T) {
	f := &framedConn{Conn: nopConn{}}

	// First handshake record whose first message is not a ServerHello.
	_, err := f.Write(record(recordTypeHandshake, 60))
	require.NoError(t, err)

	_, ok := f.serverRandom()
	assert.False(t, ok)
}

// TestClientRandomCapture is the inbound counterpart of TestServerRandomCapture:
// the resumed-TLS-1.2 offload path takes the client random from the first
// inbound handshake record (the key log only carries it on a full handshake).
func TestClientRandomCapture(t *testing.T) {
	random := testSecret(32)

	// ClientHello: HandshakeType(1) + length(3) + version(2) + random(32) + trailing.
	body := append([]byte{1, 0, 0, 70, 3, 3}, random...)
	body = append(body, make([]byte, 38)...)
	rec := append([]byte{recordTypeHandshake, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)

	f := &framedConn{Conn: nopConn{}}

	// Fed in odd chunks, like reads arriving from the kernel.
	for off := 0; off < len(rec); off += 3 {
		f.consumeRead(rec[off:min(off+3, len(rec))])
	}

	got, ok := f.clientRandom()
	require.True(t, ok)
	assert.Equal(t, random, got)

	// A later inbound handshake record (e.g. the client Finished) must not overwrite it.
	f.consumeRead(record(recordTypeHandshake, 100))

	got, ok = f.clientRandom()
	require.True(t, ok)
	assert.Equal(t, random, got)
}

func TestClientRandomCaptureRejectsNonClientHello(t *testing.T) {
	f := &framedConn{Conn: nopConn{}}

	// First inbound handshake record whose first message is not a ClientHello.
	f.consumeRead(record(recordTypeHandshake, 60))

	_, ok := f.clientRandom()
	assert.False(t, ok)
}

// TestClientRandomCaptureIgnoresInterleavedRecord pins the fix for the capture
// only appending handshake-record bodies. Interleaving a non-handshake record
// inside an unfinished ClientHello is not valid TLS, but malformed/non-conforming
// input must still not pollute the captured client random with its body bytes.
func TestClientRandomCaptureIgnoresInterleavedRecord(t *testing.T) {
	random := testSecret(32)

	// ClientHello message header + the first 10 bytes of the random.
	headA := append([]byte{1, 0, 0, 70, 3, 3}, random[:10]...)
	recA := append([]byte{recordTypeHandshake, 3, 3, byte(len(headA) >> 8), byte(len(headA))}, headA...)

	// Interleaved application-data record whose body would land in the random
	// window if the capture did not re-check the record type.
	poison := make([]byte, 32)
	for i := range poison {
		poison[i] = 0xFF
	}
	recB := append([]byte{recordTypeApplicationData, 3, 3, 0, byte(len(poison))}, poison...)

	// Remainder of the ClientHello random, in a second handshake record.
	recC := append([]byte{recordTypeHandshake, 3, 3, 0, byte(len(random[10:]))}, random[10:]...)

	f := &framedConn{Conn: nopConn{}}
	f.consumeRead(recA)
	f.consumeRead(recB)
	f.consumeRead(recC)

	got, ok := f.clientRandom()
	require.True(t, ok)
	assert.Equal(t, random, got,
		"interleaved non-handshake record must not pollute the captured client random")
}
