package ktls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash"
)

// kernelTLS12 is the TLS 1.2 version constant in the kernel's crypto_info header.
const kernelTLS12 = 0x0303

// TLS 1.2 offload matters beyond legacy clients: Linux's TLS *device* offload
// (TLS_HW, NIC inline crypto on ConnectX-6 Dx onwards) only accepts
// TLS 1.2 AES-GCM: mainline gates tls_set_device_offload on TLS_1_2_VERSION.
// TLS 1.3 sessions always run as software kTLS (TLS_SW).
//
// tls12Params describes an offloadable TLS 1.2 AES-GCM suite. Per RFC 5288
// the nonce is fixed_iv(4, from the key block) || explicit_nonce(8, carried
// in each record); the kernel manages the explicit nonce via rec_seq.
// CBC and ChaCha20 suites are not offloaded (CBC is unsupported by kTLS;
// ChaCha20 gains nothing (no NIC offload) and has different IV semantics).
type tls12Params struct {
	kernelCipher uint16
	keyLen       int
	prfHash      func() hash.Hash
}

const (
	tls12SaltLen = 4 // fixed IV ("salt") per RFC 5288
	tls12IVLen   = 8 // explicit nonce
)

// infoSize is the kernel tls12_crypto_info_aes_gcm_* struct size, derived from
// the field layout so the buffer size and the packing logic cannot disagree:
// header(4) + iv(8) + key + salt(4) + rec_seq(8).
func (p tls12Params) infoSize() int {
	return 4 + tls12IVLen + p.keyLen + tls12SaltLen + 8
}

// keyBlockLen is the key_block length for AEAD suites: two write keys and two
// fixed IVs (RFC 5246 section 6.3 / RFC 5288).
func (p tls12Params) keyBlockLen() int {
	return 2*p.keyLen + 2*tls12SaltLen
}

var tls12CipherLookup = map[uint16]tls12Params{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   {tlsCipherAESGCM128, 16, sha256.New},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {tlsCipherAESGCM128, 16, sha256.New},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         {tlsCipherAESGCM128, 16, sha256.New},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   {tlsCipherAESGCM256, 32, sha512.New384},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {tlsCipherAESGCM256, 32, sha512.New384},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         {tlsCipherAESGCM256, 32, sha512.New384},
}

// tls12KeyBlock derives the TLS 1.2 key block from the master secret
// (RFC 5246 section 6.3). The block is independent of direction, so a
// connection derives it once and packs both the TX (server-write) and RX
// (client-write) crypto_info from it.
func tls12KeyBlock(masterSecret, clientRandom, serverRandom []byte, params tls12Params) ([]byte, error) {
	if len(masterSecret) != tls12MasterLen || len(clientRandom) != 32 || len(serverRandom) != 32 {
		return nil, fmt.Errorf("ktls: malformed TLS 1.2 key material (%d/%d/%d bytes)",
			len(masterSecret), len(clientRandom), len(serverRandom))
	}

	// PRF(master_secret, "key expansion", server_random + client_random) =>
	// client_write_key, server_write_key, client_write_IV, server_write_IV.
	seed := make([]byte, 0, 64)
	seed = append(append(seed, serverRandom...), clientRandom...)

	return tls12PRF(masterSecret, "key expansion", seed, params.keyBlockLen(), params.prfHash), nil
}

// writeKeyIV slices the directional write key and fixed IV out of a key block.
// serverWrite selects the server-write material (our TX path); otherwise the
// client-write material (RX).
func (p tls12Params) writeKeyIV(keyBlock []byte, serverWrite bool) (key, salt []byte) {
	if serverWrite {
		return keyBlock[p.keyLen : 2*p.keyLen], keyBlock[2*p.keyLen+tls12SaltLen:]
	}

	return keyBlock[:p.keyLen], keyBlock[2*p.keyLen : 2*p.keyLen+tls12SaltLen]
}

// packCryptoInfo12 packs a directional key block into the kernel's
// tls12_crypto_info_* struct.
//
// The record sequence is deterministic in TLS 1.2: the only encrypted record
// either side sends during Handshake() is its Finished message (a
// NewSessionTicket goes out in plaintext before the CipherSpec change), so
// both directions continue at sequence 1.
func packCryptoInfo12(params tls12Params, keyBlock []byte, serverWrite bool, recSeq uint64) []byte {
	key, salt := params.writeKeyIV(keyBlock, serverWrite)

	buf := make([]byte, params.infoSize())
	off := 0

	binary.LittleEndian.PutUint16(buf[off:], kernelTLS12)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], params.kernelCipher)
	off += 2

	// The iv field seeds the explicit nonce; keep it in lockstep with rec_seq
	// (the receiver takes the explicit nonce from the wire, RFC 5288 section 3).
	binary.BigEndian.PutUint64(buf[off:], recSeq)
	off += tls12IVLen

	copy(buf[off:], key)
	off += params.keyLen

	copy(buf[off:], salt)
	off += tls12SaltLen

	binary.BigEndian.PutUint64(buf[off:], recSeq)

	return buf
}

// gcm builds the AES-GCM AEAD for a write key (all offloadable TLS 1.2 suites
// are AES-GCM).
func (tls12Params) gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// verifyServerFinished decrypts the server Finished record body with the
// server-write material derived from keyBlock at sequence 0, the way the
// kernel (or NIC) will. It confirms the entire TLS 1.2 derivation (server
// random capture, master secret, PRF, key/IV split) against the real wire
// bytes before the irreversible TX offload, so a mismatch falls back to
// userspace cleanly instead of shipping a corrupt first record.
func verifyServerFinished(finishedBody, keyBlock []byte, params tls12Params) bool {
	if len(finishedBody) < tls12IVLen+gcmTagLen {
		return false
	}

	key, salt := params.writeKeyIV(keyBlock, true)

	aead, err := params.gcm(key)
	if err != nil {
		return false
	}

	nonce := make([]byte, 0, tls12SaltLen+tls12IVLen)
	nonce = append(append(nonce, salt...), finishedBody[:tls12IVLen]...)
	ciphertext := finishedBody[tls12IVLen:]

	// additional_data = seq_num(8) || type(1) || version(2) || length(2); the
	// server Finished is the first record under the new keys, so seq is 0.
	plaintextLen := len(ciphertext) - gcmTagLen
	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, recordTypeHandshake, 3, 3, byte((plaintextLen >> 8) & 0xff), byte(plaintextLen & 0xff)}

	_, err = aead.Open(nil, nonce, ciphertext, aad)

	return err == nil
}

const gcmTagLen = 16

// tls12PRF implements the TLS 1.2 pseudorandom function (RFC 5246 section 5):
// P_hash over HMAC with the suite's PRF hash.
func tls12PRF(secret []byte, label string, seed []byte, length int, hashFunc func() hash.Hash) []byte {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(append(labelSeed, label...), seed...)

	mac := hmac.New(hashFunc, secret)
	out := make([]byte, 0, length)

	a := hmacOf(mac, labelSeed) // A(1)
	for len(out) < length {
		out = append(out, hmacOf(mac, a, labelSeed)...)
		a = hmacOf(mac, a)
	}

	return out[:length]
}

func hmacOf(mac hash.Hash, parts ...[]byte) []byte {
	mac.Reset()
	for _, p := range parts {
		mac.Write(p)
	}

	return mac.Sum(nil)
}
