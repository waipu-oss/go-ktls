package ktls

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeyLog = "# comment\n" +
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET 6161 dead\n" +
	"SERVER_HANDSHAKE_TRAFFIC_SECRET 6161 beef\n" +
	"CLIENT_TRAFFIC_SECRET_0 6161 0102030405060708\n" +
	"SERVER_TRAFFIC_SECRET_0 6161 1112131415161718\n"

func TestParseTrafficSecret(t *testing.T) {
	server, err := parseTrafficSecret(testKeyLog, labelServerTraffic)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}, server)

	client, err := parseTrafficSecret(testKeyLog, labelClientTraffic)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, client)

	_, err = parseTrafficSecret("CLIENT_RANDOM 6161 abcd\n", labelServerTraffic)
	require.Error(t, err)

	_, err = parseTrafficSecret("SERVER_TRAFFIC_SECRET_0 6161 nothex\n", labelServerTraffic)
	require.Error(t, err)
}

func TestKeyLogSnifferSecrets(t *testing.T) {
	sniffer := &keyLogSniffer{}
	_, err := sniffer.Write([]byte(testKeyLog))
	require.NoError(t, err)

	tx, rx, err := sniffer.secrets()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}, tx)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, rx)
}

func TestKeyLogSnifferMasterSecret(t *testing.T) {
	sniffer := &keyLogSniffer{}
	_, err := sniffer.Write([]byte("# comment\nCLIENT_RANDOM aabb 010203\n"))
	require.NoError(t, err)

	clientRandom, master, err := sniffer.masterSecret()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xaa, 0xbb}, clientRandom)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, master)

	empty := &keyLogSniffer{}
	_, _, err = empty.masterSecret()
	require.Error(t, err, "TLS 1.3 key logs have no CLIENT_RANDOM line")
}

func TestKeyLogSnifferSplitWrites(t *testing.T) {
	sniffer := &keyLogSniffer{}

	for _, chunk := range []string{"SERVER_TRAFF", "IC_SECRET_0 6161 11\nCLIENT_TRAFFIC", "_SECRET_0 6161 01\n"} {
		_, err := sniffer.Write([]byte(chunk))
		require.NoError(t, err)
	}

	tx, rx, err := sniffer.secrets()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x11}, tx)
	assert.Equal(t, []byte{0x01}, rx)
}

func TestKeyLogSnifferChain(t *testing.T) {
	var chained bytes.Buffer
	sniffer := &keyLogSniffer{chain: &chained}

	n, err := sniffer.Write([]byte(testKeyLog))
	require.NoError(t, err)
	assert.Equal(t, len(testKeyLog), n)
	assert.Equal(t, testKeyLog, chained.String())
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestKeyLogSnifferChainError(t *testing.T) {
	sniffer := &keyLogSniffer{chain: failWriter{}}

	_, err := sniffer.Write([]byte("x\n"))
	require.Error(t, err, "user key log writer errors must propagate, matching crypto/tls semantics")
}
