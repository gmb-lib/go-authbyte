// Package apikeys makes and checks API keys. A key is shown to its holder once; only an argon2id
// hash of its secret is stored ([RFC 9106 §3.1]); a presented key is checked behind a rate limit
// and a cap on concurrent derives, and a wrong, an unknown and a malformed key each cost the same
// one derive, so neither timing nor load tells them apart.
//
// A key reads <scheme>_<lookup>_<secret>. The scheme names the key family. The lookup part, 8
// characters of Crockford's Base32 from 40 random bits, is stored in clear to find the key by. The
// secret, 32 characters of unpadded base64url ([RFC 4648 §5]) from 192 random bits, is never
// stored. The stored string is a PHC string:
//
//	$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<tag>
//
// with the salt and the tag in unpadded standard base64 ([RFC 4648 §4]); the tag is argon2id over
// the secret's 32 characters.
package apikeys

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// The shape of a key and of its stored string. They are the format itself, not settings: a key
// made with other lengths would not be read by another copy of the format.
const (
	separator    = '_'
	lookupBytes  = 5  // 40 random bits
	lookupLen    = 8  // lookupBytes in Crockford's Base32
	secretBytes  = 24 // 192 random bits
	secretLen    = 32 // secretBytes in unpadded base64url
	saltLen      = 16 // the salt a key is minted with; also the shortest accepted (128 bits)
	maxSaltLen   = 64
	tagLen       = 32
	minSchemeLen = 2
	maxSchemeLen = 8
)

// lookupAlphabet is Crockford's Base32 in upper case: the digits and the letters without I, L, O
// and U, so a lookup part read aloud or copied by hand is not misread.
const lookupAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var lookupEncoding = base32.NewEncoding(lookupAlphabet).WithPadding(base32.NoPadding)

var lookupChars, secretChars = charset(lookupAlphabet), charset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

func charset(s string) (set [256]bool) {
	for i := range len(s) {
		set[s[i]] = true
	}

	return set
}

// Params are argon2id's cost: memory in KiB, passes over it, and lanes ([RFC 9106 §3.1]).
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// DefaultParams are the parameters keys are minted with unless a scheme names others: 19 MiB, two
// passes, one lane. Every key of this format minted so far uses them, so changing them for a scheme
// changes every new stored string, and the old ones then need the scheme's Floor.
func DefaultParams() Params { return Params{Memory: 19456, Iterations: 2, Parallelism: 1} }

// DefaultCeiling is the most a stored string may name unless a scheme says otherwise: the second
// recommended option of [RFC 9106 §4] (64 MiB, three passes, four lanes). It bounds what one
// tampered or corrupt stored string can make a check cost.
func DefaultCeiling() Params { return Params{Memory: 65536, Iterations: 3, Parallelism: 4} }

func (p Params) atLeast(q Params) bool {
	return p.Memory >= q.Memory && p.Iterations >= q.Iterations && p.Parallelism >= q.Parallelism
}

func (p Params) nonZero() bool { return p.Memory > 0 && p.Iterations > 0 && p.Parallelism > 0 }

func higher(p, q Params) Params {
	return Params{Memory: max(p.Memory, q.Memory), Iterations: max(p.Iterations, q.Iterations), Parallelism: max(p.Parallelism, q.Parallelism)}
}

// Config describes a key family.
type Config struct {
	// Scheme starts every key of the family: 2 to 8 lower-case letters or digits, the first a letter.
	Scheme string
	// Params are what new keys are minted with; zero means DefaultParams. Never less memory or fewer
	// passes than DefaultParams: a scheme cannot be made weaker than the keys of this format have
	// always been, by a typo or otherwise.
	Params Params
	// Floor is the least a stored string may name; zero means DefaultParams, so a service that raises
	// Params keeps its existing keys working while each check of one hands back its rehash (see
	// Result.Rehash). Never below DefaultParams, as Params.
	Floor Params
	// Ceiling is the most a stored string may name; zero means DefaultCeiling, raised to Params where
	// Params is higher.
	Ceiling Params
}

// Scheme makes keys of one family and reads their stored strings.
type Scheme struct {
	name    string
	mint    Params
	floor   Params
	ceiling Params
	rand    io.Reader
	derive  func(secret, salt []byte, p Params, n uint32) []byte
	dummy   storedHash
}

// NewScheme checks c and returns its key family.
func NewScheme(c Config) (*Scheme, error) {
	if !validScheme(c.Scheme) {
		return nil, fmt.Errorf("apikeys: scheme %q is not %d to %d lower-case letters or digits starting with a letter", c.Scheme, minSchemeLen, maxSchemeLen)
	}

	s := &Scheme{name: c.Scheme, mint: c.Params, floor: c.Floor, ceiling: c.Ceiling, rand: rand.Reader, derive: argon2id}

	if s.mint == (Params{}) {
		s.mint = DefaultParams()
	}

	if s.floor == (Params{}) {
		s.floor = DefaultParams()
	}

	if s.ceiling == (Params{}) {
		s.ceiling = higher(DefaultCeiling(), s.mint)
	}

	d := DefaultParams()

	switch {
	case !s.mint.nonZero() || !s.floor.nonZero():
		return nil, errors.New("apikeys: a scheme's parameters must not be zero")
	case s.floor.Memory < d.Memory || s.floor.Iterations < d.Iterations: // the minted ones are at least the floor
		return nil, fmt.Errorf("apikeys: a scheme's parameters must not be below %d KiB and %d passes", d.Memory, d.Iterations)
	case !s.mint.atLeast(s.floor):
		return nil, errors.New("apikeys: a scheme's minted parameters are below its floor")
	case !s.ceiling.atLeast(s.mint):
		return nil, errors.New("apikeys: a scheme's ceiling is below its minted parameters")
	}

	// The hash an unknown or malformed key is checked against, so that it costs what a known key
	// costs. Its salt and tag come from the system's randomness, never from Rand, and its secret
	// exists nowhere; a check against it is refused whatever the comparison says.
	s.dummy = storedHash{params: s.mint, salt: make([]byte, saltLen), tag: make([]byte, tagLen)}
	if _, err := rand.Read(s.dummy.salt); err != nil {
		return nil, fmt.Errorf("apikeys: %w", err)
	}

	if _, err := rand.Read(s.dummy.tag); err != nil {
		return nil, fmt.Errorf("apikeys: %w", err)
	}

	return s, nil
}

func validScheme(name string) bool {
	if len(name) < minSchemeLen || len(name) > maxSchemeLen || name[0] < 'a' || name[0] > 'z' {
		return false
	}

	for i := range len(name) {
		if c := name[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}

	return true
}

func argon2id(secret, salt []byte, p Params, n uint32) []byte {
	return argon2.IDKey(secret, salt, p.Iterations, p.Memory, p.Parallelism, n)
}

// Minted is a new key: the key itself, to show its holder once; its lookup part, to store in clear
// and find the key by; and Hash, the string to store in the key's place.
type Minted struct {
	Key    Secret
	Lookup string
	Hash   string
}

// Mint makes a new key. Nothing about it is kept; the caller stores Lookup and Hash and shows Key
// once. The store must hold lookup parts unique and the caller mint again on a clash: 40 random bits
// make one rare, not impossible.
func (s *Scheme) Mint() (Minted, error) {
	buf := make([]byte, lookupBytes+secretBytes+saltLen)
	defer clear(buf)

	if _, err := io.ReadFull(s.rand, buf); err != nil {
		return Minted{}, fmt.Errorf("apikeys: mint: %w", err)
	}

	lookup := lookupEncoding.EncodeToString(buf[:lookupBytes])
	secret := base64.RawURLEncoding.EncodeToString(buf[lookupBytes : lookupBytes+secretBytes])
	k := parsedKey{lookup: lookup, secret: []byte(secret)}

	return Minted{
		Key:    Secret{v: s.name + string(separator) + lookup + string(separator) + secret},
		Lookup: lookup,
		Hash:   s.hashWith(k, buf[lookupBytes+secretBytes:], s.mint),
	}, nil
}

type parsedKey struct {
	lookup string
	secret []byte
}

// parse reads a key of this scheme. Its length is checked first, so an input of any size costs the
// same; every refusal is ErrInvalid and names nothing of the input.
func (s *Scheme) parse(key string) (parsedKey, error) {
	n := len(s.name)
	if len(key) != n+1+lookupLen+1+secretLen || key[:n] != s.name || key[n] != separator || key[n+1+lookupLen] != separator {
		return parsedKey{}, ErrInvalid
	}

	lookup, secret := key[n+1:n+1+lookupLen], key[n+2+lookupLen:]

	for i := range len(lookup) {
		if !lookupChars[lookup[i]] {
			return parsedKey{}, ErrInvalid
		}
	}

	for i := range len(secret) {
		if !secretChars[secret[i]] {
			return parsedKey{}, ErrInvalid
		}
	}

	return parsedKey{lookup: lookup, secret: []byte(secret)}, nil
}

func (s *Scheme) hashWith(k parsedKey, salt []byte, p Params) string {
	return encodeStored(p, salt, s.derive(k.secret, salt, p, tagLen))
}

// rehashTo returns the parameters a stored string at p should be rehashed to, and whether it should:
// each field raised to the scheme's minted value where it is below it, none ever lowered.
func (s *Scheme) rehashTo(p Params) (Params, bool) {
	to := higher(p, s.mint)

	return to, to != p
}

type storedHash struct {
	params    Params
	salt, tag []byte
}

func encodeStored(p Params, salt, tag []byte) string {
	return "$argon2id$v=" + strconv.Itoa(argon2.Version) +
		"$m=" + strconv.FormatUint(uint64(p.Memory), 10) +
		",t=" + strconv.FormatUint(uint64(p.Iterations), 10) +
		",p=" + strconv.FormatUint(uint64(p.Parallelism), 10) +
		"$" + base64.RawStdEncoding.EncodeToString(salt) +
		"$" + base64.RawStdEncoding.EncodeToString(tag)
}

// maxStoredLen bounds the stored string read before it is split: the longest well-formed one, at
// the largest values the fields can hold, is well under it.
const maxStoredLen = 256

// decodeStored reads a stored string strictly: one spelling only (no extra field, parameter or
// character, no padding, no leading zero), argon2id at version 19, a salt and a tag of the
// accepted lengths, and parameters between the scheme's floor and ceiling. Anything else is
// ErrStoredHash, so a corrupt or tampered string can neither panic a check nor make it cheap or
// ruinously dear.
func (s *Scheme) decodeStored(h string) (storedHash, error) {
	if len(h) > maxStoredLen {
		return storedHash{}, storedErr("too long")
	}

	f := strings.Split(h, "$")
	if len(f) != 6 || f[0] != "" || f[1] != "argon2id" || f[2] != "v="+strconv.Itoa(argon2.Version) {
		return storedHash{}, storedErr("not argon2id version 19")
	}

	ps := strings.Split(f[3], ",")
	if len(ps) != 3 {
		return storedHash{}, storedErr("not three parameters")
	}

	m, okM := decimal(ps[0], "m=", 32)
	t, okT := decimal(ps[1], "t=", 32)
	p, okP := decimal(ps[2], "p=", 8)

	if !okM || !okT || !okP {
		return storedHash{}, storedErr("parameters not m, t and p in decimal")
	}

	salt, okS := strictBase64(f[4])
	tag, okG := strictBase64(f[5])

	if !okS || !okG || len(salt) < saltLen || len(salt) > maxSaltLen || len(tag) != tagLen {
		return storedHash{}, storedErr("salt or tag malformed or of the wrong length")
	}

	st := storedHash{params: Params{Memory: uint32(m), Iterations: uint32(t), Parallelism: uint8(p)}, salt: salt, tag: tag}

	// The floor is never zero (NewScheme refuses one), so this also refuses the zero passes or lanes
	// that would panic argon2id.
	if !st.params.atLeast(s.floor) || !s.ceiling.atLeast(st.params) {
		return storedHash{}, storedErr("parameters outside the scheme's floor and ceiling")
	}

	return st, nil
}

func storedErr(reason string) error { return fmt.Errorf("%w: %s", ErrStoredHash, reason) }

func decimal(field, name string, bits int) (uint64, bool) {
	v, ok := strings.CutPrefix(field, name)
	if !ok {
		return 0, false
	}

	n, err := strconv.ParseUint(v, 10, bits)
	if err != nil || strconv.FormatUint(n, 10) != v {
		return 0, false
	}

	return n, true
}

// strictBase64 decodes unpadded standard base64 and accepts only its canonical spelling: the
// decoder skips line breaks, which re-encoding catches.
func strictBase64(s string) ([]byte, bool) {
	b, err := base64.RawStdEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawStdEncoding.EncodeToString(b) != s {
		return nil, false
	}

	return b, true
}
