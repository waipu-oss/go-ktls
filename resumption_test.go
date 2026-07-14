package ktls

import (
	"bytes"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMasterExtraRoundTrip(t *testing.T) {
	t.Parallel()

	master := bytes.Repeat([]byte{0xAB}, tls12MasterLen)

	// Coexists with a foreign Extra entry from another layer.
	ss := &tls.SessionState{Extra: [][]byte{[]byte("other-layer\x01data")}}
	appendMasterExtra(ss, master)

	got, ok := masterFromExtra(ss)
	require.True(t, ok)
	assert.Equal(t, master, got)

	// No entry stashed.
	_, ok = masterFromExtra(&tls.SessionState{})
	assert.False(t, ok)

	// Our prefix but a wrong length must not be mistaken for a master secret.
	truncated := append(append([]byte{}, extraMasterPrefix...), 0x00)
	_, ok = masterFromExtra(&tls.SessionState{Extra: [][]byte{truncated}})
	assert.False(t, ok)
}
