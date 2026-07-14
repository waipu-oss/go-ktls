package ktls

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refExpandLabel is an independent HKDF-Expand-Label implementation (RFC 8446
// section 7.1 + RFC 5869 section 2.3) built directly on HMAC, used to
// cross-check hkdfExpandLabel. The end-to-end validation against crypto/tls
// happens in TestSessionTicketRecordSequence.
func refExpandLabel(h func() hash.Hash, secret []byte, label string, length int) []byte {
	fullLabel := "tls13 " + label
	info := []byte{byte(length >> 8), byte(length), byte(len(fullLabel))}
	info = append(info, fullLabel...)
	info = append(info, 0)

	var out, prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(h, secret)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}

	return out[:length]
}

func testSecret(n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = byte(i + 1)
	}

	return s
}

func TestHKDFExpandLabelMatchesReference(t *testing.T) {
	for suiteID, params := range cipherLookup {
		secret := testSecret(params.secretLen)

		for _, label := range []string{"key", "iv", "traffic upd"} {
			for _, length := range []int{params.keyLen, params.saltLen + params.ivLen, params.secretLen} {
				got, err := hkdfExpandLabel(secret, label, length, params.hashFunc)
				require.NoError(t, err)
				assert.Equal(t, refExpandLabel(params.hashFunc, secret, label, length), got,
					"suite 0x%04x label %q length %d", suiteID, label, length)
			}
		}
	}
}

func TestBuildCryptoInfoLayout(t *testing.T) {
	const recSeq = uint64(0x0102030405060708)

	for suiteID, params := range cipherLookup {
		secret := testSecret(params.secretLen)

		info, err := buildCryptoInfo(secret, suiteID, recSeq)
		require.NoError(t, err)
		require.Len(t, info, params.infoSize, "suite 0x%04x", suiteID)

		key, err := hkdfExpandLabel(secret, "key", params.keyLen, params.hashFunc)
		require.NoError(t, err)
		iv, err := hkdfExpandLabel(secret, "iv", params.saltLen+params.ivLen, params.hashFunc)
		require.NoError(t, err)

		off := 0
		assert.Equal(t, uint16(kernelTLS13), binary.LittleEndian.Uint16(info[off:]), "version")
		off += 2
		assert.Equal(t, params.kernelCipher, binary.LittleEndian.Uint16(info[off:]), "cipher type")
		off += 2
		assert.Equal(t, iv[params.saltLen:], info[off:off+params.ivLen], "iv field")
		off += params.ivLen
		assert.Equal(t, key, info[off:off+params.keyLen], "key field")
		off += params.keyLen
		assert.Equal(t, iv[:params.saltLen], info[off:off+params.saltLen], "salt field")
		off += params.saltLen
		assert.Equal(t, recSeq, binary.BigEndian.Uint64(info[off:]), "rec_seq field")
	}
}

func TestBuildCryptoInfoUnknownSuite(t *testing.T) {
	_, err := buildCryptoInfo(testSecret(32), 0xcca8, 0)
	require.Error(t, err)
}

// TestComputeTXSeqRoundtrip covers all three suites, including ChaCha20-
// Poly1305, which the real-handshake test can't reach (crypto/tls picks
// AES-GCM under AES-NI).
func TestComputeTXSeqRoundtrip(t *testing.T) {
	for suiteID, params := range cipherLookup {
		t.Run(fmt.Sprintf("suite_%04x", suiteID), func(t *testing.T) {
			secret := testSecret(params.secretLen)

			// One ticket at seq 0, kernel continues at 1 (the crypto/tls case).
			ticket := sealRecord(t, secret, suiteID, 0, make([]byte, 120))
			got, err := computeTXSeq(ticket, secret, suiteID)
			require.NoError(t, err)
			assert.Equal(t, uint64(1), got)

			// A second ticket would sit at seq 1, kernel continues at 2.
			// crypto/tls never sends two, but computeTXSeq verifies the sequence
			// rather than guessing, so this stays correct instead of silently 0.
			ticket1 := sealRecord(t, secret, suiteID, 1, make([]byte, 120))
			got, err = computeTXSeq(ticket1, secret, suiteID)
			require.NoError(t, err)
			assert.Equal(t, uint64(2), got)

			// A record that opens at neither sequence (stands in for the
			// handshake-key Finished, or any unexpected layout) is refused, so
			// the caller falls back to userspace instead of seeding a wrong seq.
			_, err = computeTXSeq(record(recordTypeApplicationData, 53), secret, suiteID)
			require.Error(t, err)
		})
	}
}

func TestDeriveNextSecret(t *testing.T) {
	for suiteID, params := range cipherLookup {
		secret := testSecret(params.secretLen)

		next, err := deriveNextSecret(secret, suiteID)
		require.NoError(t, err)

		want, err := hkdfExpandLabel(secret, "traffic upd", params.secretLen, params.hashFunc)
		require.NoError(t, err)
		assert.Equal(t, want, next, "suite 0x%04x", suiteID)
	}
}
