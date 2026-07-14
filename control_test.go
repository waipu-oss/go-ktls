package ktls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAlert(t *testing.T) {
	tests := []struct {
		name            string
		level, desc     byte
		wantCloseNotify bool
		wantErr         bool
	}{
		{name: "close_notify", level: 1, desc: alertCloseNotify, wantCloseNotify: true},
		{name: "user_canceled ignored", level: 1, desc: alertUserCanceled},
		{name: "fatal handshake_failure", level: 2, desc: 40, wantErr: true},
		{name: "fatal bad_record_mac", level: 2, desc: 20, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closeNotify, err := parseAlert(tt.level, tt.desc)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantCloseNotify, closeNotify)
		})
	}
}

func TestParseKeyUpdates(t *testing.T) {
	keyUpdate := func(req byte) []byte { return []byte{handshakeTypeKeyUpdate, 0, 0, 1, req} }

	tests := []struct {
		name        string
		buf         []byte
		wantRest    int // length of expected remainder
		wantTXRekey bool
		wantErr     bool
	}{
		{name: "empty", buf: nil},
		{name: "not requested", buf: keyUpdate(keyUpdateNotRequested)},
		{name: "requested", buf: keyUpdate(keyUpdateRequested), wantTXRekey: true},
		{
			name:        "coalesced messages",
			buf:         append(keyUpdate(keyUpdateNotRequested), keyUpdate(keyUpdateRequested)...),
			wantTXRekey: true,
		},
		{name: "partial header", buf: []byte{handshakeTypeKeyUpdate, 0}, wantRest: 2},
		{name: "header complete body in flight", buf: []byte{handshakeTypeKeyUpdate, 0, 0, 1}, wantRest: 4},
		{name: "wrong message type (HelloRequest)", buf: []byte{0, 0, 0, 0}, wantErr: true},
		{name: "NewSessionTicket rejected", buf: []byte{4, 0, 0, 1, 0}, wantErr: true},
		{name: "bad length", buf: []byte{handshakeTypeKeyUpdate, 0, 0, 2, 0, 0}, wantErr: true},
		{name: "invalid request_update", buf: []byte{handshakeTypeKeyUpdate, 0, 0, 1, 2}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rest, txRekey, err := parseKeyUpdates(tt.buf)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantTXRekey, txRekey)
			assert.Len(t, rest, tt.wantRest)
		})
	}
}
