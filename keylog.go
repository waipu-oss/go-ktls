package ktls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
)

// NSS key log labels written by crypto/tls: per-direction application traffic
// secrets for TLS 1.3, client random + master secret for TLS 1.2.
const (
	labelServerTraffic = "SERVER_TRAFFIC_SECRET_0"
	labelClientTraffic = "CLIENT_TRAFFIC_SECRET_0"
	labelClientRandom  = "CLIENT_RANDOM"
)

// keyLogSniffer captures the NSS key log lines crypto/tls emits during the
// handshake so the TLS 1.3 traffic secrets can be handed to the kernel.
type keyLogSniffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	chain io.Writer // user-provided KeyLogWriter, if any
}

func (k *keyLogSniffer) Write(p []byte) (int, error) {
	k.mu.Lock()
	k.buf.Write(p)
	k.mu.Unlock()

	if k.chain != nil {
		if _, err := k.chain.Write(p); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// snapshot returns the captured key log so far.
func (k *keyLogSniffer) snapshot() string {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.buf.String()
}

// secrets parses the captured key log in a single pass and returns the
// server (TX) and client (RX) application traffic secrets.
func (k *keyLogSniffer) secrets() (txSecret, rxSecret []byte, err error) {
	for line := range strings.SplitSeq(k.snapshot(), "\n") {
		label, _, secret, ok := splitKeyLogLine(line)
		if !ok {
			continue
		}

		var dst *[]byte
		switch label {
		case labelServerTraffic:
			dst = &txSecret
		case labelClientTraffic:
			dst = &rxSecret
		default:
			continue
		}

		if *dst, err = hex.DecodeString(secret); err != nil {
			return nil, nil, fmt.Errorf("ktls: malformed %s key log line: %w", label, err)
		}
	}

	if txSecret == nil {
		return nil, nil, fmt.Errorf("ktls: %s not found in key log", labelServerTraffic)
	}
	if rxSecret == nil {
		return nil, nil, fmt.Errorf("ktls: %s not found in key log", labelClientTraffic)
	}

	return txSecret, rxSecret, nil
}

// masterSecret parses the TLS 1.2 key log line and returns the client random
// and the master secret (RFC 5246 key expansion inputs).
func (k *keyLogSniffer) masterSecret() (clientRandom, master []byte, err error) {
	for line := range strings.SplitSeq(k.snapshot(), "\n") {
		label, random, secret, ok := splitKeyLogLine(line)
		if !ok || label != labelClientRandom {
			continue
		}

		if clientRandom, err = hex.DecodeString(random); err != nil {
			return nil, nil, fmt.Errorf("ktls: malformed %s client random: %w", labelClientRandom, err)
		}
		if master, err = hex.DecodeString(secret); err != nil {
			return nil, nil, fmt.Errorf("ktls: malformed %s master secret: %w", labelClientRandom, err)
		}

		return clientRandom, master, nil
	}

	return nil, nil, fmt.Errorf("ktls: %s not found in key log", labelClientRandom)
}

// parseTrafficSecret extracts the secret for the given label from an NSS key
// log; used by tests to cross-check captured secrets.
func parseTrafficSecret(keyLog, label string) ([]byte, error) {
	for line := range strings.SplitSeq(keyLog, "\n") {
		l, _, secret, ok := splitKeyLogLine(line)
		if !ok || l != label {
			continue
		}

		decoded, err := hex.DecodeString(secret)
		if err != nil {
			return nil, fmt.Errorf("ktls: malformed %s key log line: %w", label, err)
		}

		return decoded, nil
	}

	return nil, fmt.Errorf("ktls: %s not found in key log", label)
}

// splitKeyLogLine splits an NSS key log line into its three space-separated
// fields ("<label> <client_random_hex> <secret_hex>") without allocating.
func splitKeyLogLine(line string) (label, random, secret string, ok bool) {
	label, rest, ok := strings.Cut(line, " ")
	if !ok {
		return "", "", "", false
	}

	random, secret, ok = strings.Cut(rest, " ")
	if !ok || secret == "" || strings.ContainsRune(secret, ' ') {
		return "", "", "", false
	}

	return label, random, secret, true
}
