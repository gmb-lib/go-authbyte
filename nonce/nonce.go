// Package nonce implements the server-issued DPoP-Nonce (RFC 9449 §8) as a
// stateless, HMAC-authenticated token. A nonce encodes its own issue time and
// a MAC, so any pod can verify a nonce another pod issued without shared
// storage — replay protection comes from the per-request `jti` cache, not the
// nonce, so nonces are reusable until they expire.
package nonce

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// ErrInvalid is returned when a nonce fails verification (bad MAC, malformed,
// or expired).
var ErrInvalid = errors.New("invalid dpop nonce")

// Issuer mints and verifies server nonces. The HMAC key is generated per pod;
// because nonces are short-lived and only bound the freshness of DPoP proofs,
// a per-pod key is sufficient (a nonce issued by one pod and presented to
// another simply triggers a fresh challenge).
type Issuer struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

// New returns a nonce issuer with a random per-process key and the given TTL.
func New(ttl time.Duration) (*Issuer, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return &Issuer{key: key, ttl: ttl, now: time.Now}, nil
}

// Issue returns a fresh nonce valid for the configured TTL.
func (i *Issuer) Issue() string {
	ts := uint64(i.now().UTC().Unix())

	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, ts)

	mac := i.mac(payload)
	raw := append(payload, mac...)

	return base64.RawURLEncoding.EncodeToString(raw)
}

// Verify checks the nonce's MAC and that it is within the TTL (plus the given
// leeway for clock skew).
func (i *Issuer) Verify(nonce string, leeway time.Duration) error {
	if nonce == "" {
		return ErrInvalid
	}

	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 8+sha256.Size {
		return ErrInvalid
	}

	payload, mac := raw[:8], raw[8:]
	if !hmac.Equal(mac, i.mac(payload)) {
		return ErrInvalid
	}

	issued := time.Unix(int64(binary.BigEndian.Uint64(payload)), 0).UTC()
	if i.now().UTC().Sub(issued) > i.ttl+leeway {
		return ErrInvalid
	}

	return nil
}

func (i *Issuer) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, i.key)
	_, _ = h.Write(payload)

	return h.Sum(nil)
}
