package ktls

import (
	"bytes"
	"crypto/tls"
)

// tls12MasterLen is the fixed TLS 1.2 master secret length (RFC 5246 section 8.1).
const tls12MasterLen = 48

// extraMasterPrefix tags our entry in SessionState.Extra, a public field
// crypto/tls round-trips but ignores. Entries carry an id+version prefix so
// layers coexist. Stashing the master here (rather than parsing crypto/tls'
// internal SessionState encoding) lets a resumed TLS 1.2 handshake, which logs
// no CLIENT_RANDOM, recover it and stay kTLS-offloadable.
var extraMasterPrefix = []byte("ktls-tls12m\x01")

// appendMasterExtra stashes a TLS 1.2 master secret (tagged) in ss.Extra, to be
// recovered by masterFromExtra on a later resumption.
func appendMasterExtra(ss *tls.SessionState, master []byte) {
	entry := make([]byte, 0, len(extraMasterPrefix)+len(master))
	entry = append(entry, extraMasterPrefix...)
	entry = append(entry, master...)
	ss.Extra = append(ss.Extra, entry)
}

// masterFromExtra returns the TLS 1.2 master secret previously stashed by
// appendMasterExtra, or false if no well-formed entry is present.
func masterFromExtra(ss *tls.SessionState) ([]byte, bool) {
	for _, e := range ss.Extra {
		if len(e) != len(extraMasterPrefix)+tls12MasterLen || !bytes.HasPrefix(e, extraMasterPrefix) {
			continue
		}

		master := make([]byte, tls12MasterLen)
		copy(master, e[len(extraMasterPrefix):])

		return master, true
	}

	return nil, false
}
