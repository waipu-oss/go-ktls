package ktls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// Kernel cipher type constants from include/uapi/linux/tls.h.
const (
	tlsCipherAESGCM128        = 51
	tlsCipherAESGCM256        = 52
	tlsCipherChaCha20Poly1305 = 54

	// kernelTLS13 is the TLS 1.3 version constant in the kernel's crypto_info header.
	kernelTLS13 = 0x0304
)

// cipherParams describes the kernel crypto_info layout for a TLS 1.3 cipher suite.
// The kernel structs are: 4 byte header (version + cipher type), iv, key, salt, rec_seq.
// For AES-GCM the TLS 1.3 12-byte IV is split into salt (first 4 bytes) and iv (last 8);
// ChaCha20-Poly1305 uses the full 12-byte IV with no salt.
type cipherParams struct {
	kernelCipher uint16
	keyLen       int
	ivLen        int
	saltLen      int
	secretLen    int // hash output length, also the traffic secret length
	hashFunc     func() hash.Hash
	infoSize     int
}

// cipherLookup covers the three TLS 1.3 cipher suites crypto/tls implements.
// (RFC 8446 also defines two AES-CCM suites, which Go never negotiates, so
// every TLS 1.3 connection crypto/tls establishes is eligible.)
var cipherLookup = map[uint16]cipherParams{
	0x1301: {tlsCipherAESGCM128, 16, 8, 4, 32, sha256.New, 40},         // TLS_AES_128_GCM_SHA256
	0x1302: {tlsCipherAESGCM256, 32, 8, 4, 48, sha512.New384, 56},      // TLS_AES_256_GCM_SHA384
	0x1303: {tlsCipherChaCha20Poly1305, 32, 12, 0, 32, sha256.New, 56}, // TLS_CHACHA20_POLY1305_SHA256
}

// trafficKeyIV derives the record key and IV from a traffic secret
// (RFC 8446 section 7.3).
func trafficKeyIV(secret []byte, params cipherParams) (key, iv []byte, err error) {
	key, err = hkdfExpandLabel(secret, "key", params.keyLen, params.hashFunc)
	if err != nil {
		return nil, nil, err
	}

	iv, err = hkdfExpandLabel(secret, "iv", params.saltLen+params.ivLen, params.hashFunc)
	if err != nil {
		return nil, nil, err
	}

	return key, iv, nil
}

// recordNonce fills nonce with the per-record nonce: the IV with the 64-bit
// record sequence number XORed into its trailing 8 bytes (RFC 8446 section 5.3).
func recordNonce(nonce, iv []byte, seq uint64) {
	copy(nonce, iv)
	for i := range 8 {
		nonce[len(nonce)-8+i] ^= byte((seq >> (8 * (7 - i))) & 0xff)
	}
}

// buildCryptoInfo derives key and IV from the traffic secret (RFC 8446 section 7.3)
// and packs them into the kernel's tls12_crypto_info_* struct layout for setsockopt.
func buildCryptoInfo(secret []byte, cipherSuiteID uint16, recSeq uint64) ([]byte, error) {
	params, ok := cipherLookup[cipherSuiteID]
	if !ok {
		return nil, fmt.Errorf("ktls: unsupported cipher suite 0x%04x", cipherSuiteID)
	}

	key, iv, err := trafficKeyIV(secret, params)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, params.infoSize)
	off := 0

	binary.LittleEndian.PutUint16(buf[off:], kernelTLS13)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], params.kernelCipher)
	off += 2

	copy(buf[off:], iv[params.saltLen:])
	off += params.ivLen

	copy(buf[off:], key)
	off += params.keyLen

	copy(buf[off:], iv[:params.saltLen])
	off += params.saltLen

	binary.BigEndian.PutUint64(buf[off:], recSeq)

	return buf, nil
}

// deriveNextSecret computes the next application traffic secret (RFC 8446 section 7.2):
// application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
func deriveNextSecret(currentSecret []byte, cipherSuiteID uint16) ([]byte, error) {
	params, ok := cipherLookup[cipherSuiteID]
	if !ok {
		return nil, fmt.Errorf("ktls: unsupported cipher suite 0x%04x", cipherSuiteID)
	}

	return hkdfExpandLabel(currentSecret, "traffic upd", params.secretLen, params.hashFunc)
}

// computeTXSeq returns the application-key record sequence the kernel TX path
// continues with. Handshake-key and application-key records are
// indistinguishable on the wire, so we trial-decrypt the last written record
// with the application traffic key instead of counting.
//
// When crypto/tls sends a NewSessionTicket it is a single application-key
// record at sequence 0 (the first record under the application traffic key),
// so the last record is
// that ticket and the kernel continues at 1. We also accept sequence 1
// (kernel continues at 2) so a future crypto/tls that emits two tickets stays correct
// rather than silently wrong.
//
// A record that opens at neither sequence gets no offload: we return an error
// that prepareKeys maps to a userspace fallback (errFraming). This covers two
// distinct layouts we cannot tell apart without a TX application-record count:
//   - No ticket at all: SessionTicketsDisabled, or a TLS 1.3 client that does
//     not advertise psk_dhe_ke, so crypto/tls sends none. wLast is then the
//     handshake-key Finished, which opens under no application sequence. The
//     kernel could correctly continue at 0 here, so these connections lose
//     offload and fall back to userspace, a deliberate trade to avoid the
//     second case.
//   - Three or more application-key records: wLast sits at real sequence ≥2
//     (sequences 0 and 1 are accepted above) and would seed the kernel too low,
//     shipping the first response record at the wrong number and tripping
//     bad_record_mac on an already-irreversible offload. Failing closed keeps
//     that connection in userspace instead.
func computeTXSeq(lastRecord, txSecret []byte, cipherSuiteID uint16) (uint64, error) {
	if len(lastRecord) < recordHeaderLen {
		return 0, errors.New("ktls: no outgoing record captured during handshake")
	}

	params, ok := cipherLookup[cipherSuiteID]
	if !ok {
		return 0, fmt.Errorf("ktls: unsupported cipher suite 0x%04x", cipherSuiteID)
	}

	key, iv, err := trafficKeyIV(txSecret, params)
	if err != nil {
		return 0, err
	}

	aead, err := aeadForSuite(cipherSuiteID, key)
	if err != nil {
		return 0, err
	}

	nonce := make([]byte, len(iv))
	for seq := uint64(0); seq <= 1; seq++ {
		recordNonce(nonce, iv, seq)
		if _, err := aead.Open(nil, nonce, lastRecord[recordHeaderLen:], lastRecord[:recordHeaderLen]); err == nil {
			return seq + 1, nil
		}
	}

	return 0, errors.New("ktls: last outgoing record opened at neither TX sequence 0 nor 1; unexpected TLS 1.3 record layout")
}

// aeadForSuite returns the AEAD for a TLS 1.3 cipher suite.
func aeadForSuite(cipherSuiteID uint16, key []byte) (cipher.AEAD, error) {
	switch cipherSuiteID {
	case 0x1301, 0x1302: // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		return cipher.NewGCM(block)
	case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("ktls: unsupported cipher suite 0x%04x", cipherSuiteID)
	}
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446 section 7.1.
func hkdfExpandLabel(secret []byte, label string, length int, hashFunc func() hash.Hash) ([]byte, error) {
	fullLabel := "tls13 " + label

	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1)
	hkdfLabel = binary.BigEndian.AppendUint16(hkdfLabel, uint16(length&0xffff))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)&0xff))
	hkdfLabel = append(hkdfLabel, fullLabel...)
	hkdfLabel = append(hkdfLabel, 0) // empty context

	return hkdf.Expand(hashFunc, secret, string(hkdfLabel), length)
}
