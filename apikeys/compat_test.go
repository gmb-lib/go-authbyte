package apikeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

// The existing key format this package must keep: keys and stored strings minted elsewhere from
// known randomness. Each mint read 45 bytes (lookup 5, secret 24, salt 16) counting up from a first
// byte in fixed steps, wrapping at 256, so the randomness is rebuilt here instead of written out.
var existingFormatVectors = []struct {
	name        string
	first, step byte
	lookup      string
	stored      string
}{
	{"counting from 0x11", 0x11, 7, "24C1Y9HD", "$argon2id$v=19$m=19456,t=2,p=1$3OPq8fj/Bg0UGyIpMDc+RQ$LNIeC2T2Atq7M7iQPTs86n6JVoGAo+5GPvva/5HpVGQ"},
	{"counting from 0x80", 0x80, 7, "G23RX5CW", "$argon2id$v=19$m=19456,t=2,p=1$S1JZYGdudXyDipGYn6attA$u3XyLnh2472I7Z2A4U851kWlQyn+6Fqposb4fHza3U0"},
	{"counting from 0xe3", 0xe3, 7, "WFNF3Y7Z", "$argon2id$v=19$m=19456,t=2,p=1$rrW8w8rR2N/m7fT7AgkQFw$cEvrL6pf2KIwPO+Se0uVDwWphXCAsOqs40AnlXeFd9M"},
	{"all zero", 0x00, 0, "00000000", "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$8839G8V5ai6IbLySg08Z3XffyaawW69nymzvMOpbsaw"},
	{"all ones", 0xff, 0, "ZZZZZZZZ", "$argon2id$v=19$m=19456,t=2,p=1$/////////////////////w$4eXURa4OL6lEVH6f6nYzZ1aexA/B1O4GXmw3DZVs9kM"},
}

func counting(first, step byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)*step
	}

	return out
}

func mintFrom(t *testing.T, first, step byte) (*Scheme, Minted) {
	t.Helper()

	s, err := NewScheme(Config{Scheme: "vk"})
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}

	s.rand = bytes.NewReader(counting(first, step, lookupBytes+secretBytes+saltLen))

	k, err := s.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	return s, k
}

func TestMintMatchesTheExistingFormat(t *testing.T) {
	for _, vec := range existingFormatVectors {
		_, k := mintFrom(t, vec.first, vec.step)

		if k.Lookup != vec.lookup {
			t.Errorf("%s: lookup part %q, want %q", vec.name, k.Lookup, vec.lookup)
		}

		if k.Hash != vec.stored {
			t.Errorf("%s: stored string\n got %s\nwant %s", vec.name, k.Hash, vec.stored)
		}
	}
}

func TestVerifiesKeysOfTheExistingFormat(t *testing.T) {
	for _, vec := range existingFormatVectors {
		s, k := mintFrom(t, vec.first, vec.step)

		store := newMemStore()
		store.rows[vec.lookup] = vec.stored

		v, err := s.NewVerifier(store.lookup, VerifierConfig{})
		if err != nil {
			t.Fatal(err)
		}

		res, err := v.Verify(context.Background(), "caller", k.Key.Reveal())
		if err != nil {
			t.Errorf("%s: the existing key is refused: %v", vec.name, err)

			continue
		}

		if res.Lookup != vec.lookup || res.Rehash != "" {
			t.Errorf("%s: result %+v", vec.name, res)
		}

		if _, err := v.Verify(context.Background(), "caller", mutateSecret(t, s, k.Key.Reveal())); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: a wrong secret: got %v, want ErrInvalid", vec.name, err)
		}
	}
}

func TestHashMatchesTheExistingFormat(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "vk"})
	if err != nil {
		t.Fatal(err)
	}

	pk := parsedKey{lookup: "00000000", secret: []byte("zz-fixed-known-secret-0123456789")}
	salt := counting(0xa0, 1, saltLen)

	const want = "$argon2id$v=19$m=19456,t=2,p=1$oKGio6SlpqeoqaqrrK2urw$Xt4qvmddTu9b3WdIXVAsLsGKhPyjzw96qHXfo87Gbf0"

	if got := s.hashWith(pk, salt, DefaultParams()); got != want {
		t.Fatalf("stored string\n got %s\nwant %s", got, want)
	}
}

func TestStoredStringsAreReadStrictly(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "vk"})
	if err != nil {
		t.Fatal(err)
	}

	good := existingFormatVectors[0].stored
	head := "$argon2id$v=19$m=19456,t=2,p=1$"
	salt, tag := "3OPq8fj/Bg0UGyIpMDc+RQ", "LNIeC2T2Atq7M7iQPTs86n6JVoGAo+5GPvva/5HpVGQ"

	if good != head+salt+"$"+tag {
		t.Fatal("the test's parts do not rebuild the vector")
	}

	if _, err := s.decodeStored(good); err != nil {
		t.Fatalf("the well-formed stored string is refused: %v", err)
	}

	enc := base64.RawStdEncoding.EncodeToString
	short, long := enc(make([]byte, saltLen-1)), enc(make([]byte, maxSaltLen+1))
	tag31, tag33 := enc(make([]byte, tagLen-1)), enc(make([]byte, tagLen+1))

	for name, in := range map[string]string{
		"empty":                  "",
		"argon2i":                "$argon2i$v=19$m=19456,t=2,p=1$" + salt + "$" + tag,
		"argon2d":                "$argon2d$v=19$m=19456,t=2,p=1$" + salt + "$" + tag,
		"version 16":             "$argon2id$v=16$m=19456,t=2,p=1$" + salt + "$" + tag,
		"text after the version": "$argon2id$v=19x$m=19456,t=2,p=1$" + salt + "$" + tag,
		"text after the last":    "$argon2id$v=19$m=19456,t=2,p=1x$" + salt + "$" + tag,
		"an extra parameter":     "$argon2id$v=19$m=19456,t=2,p=1,x=1$" + salt + "$" + tag,
		"a repeated parameter":   "$argon2id$v=19$m=19456,m=19456,p=1$" + salt + "$" + tag,
		"reordered parameters":   "$argon2id$v=19$t=2,m=19456,p=1$" + salt + "$" + tag,
		"a missing parameter":    "$argon2id$v=19$m=19456,t=2$" + salt + "$" + tag,
		"a leading zero":         "$argon2id$v=19$m=019456,t=2,p=1$" + salt + "$" + tag,
		"a plus sign":            "$argon2id$v=19$m=+19456,t=2,p=1$" + salt + "$" + tag,
		"parallelism over 255":   "$argon2id$v=19$m=19456,t=2,p=256$" + salt + "$" + tag,
		"memory over 32 bits":    "$argon2id$v=19$m=4294967296,t=2,p=1$" + salt + "$" + tag,
		"padded salt":            head + salt + "==$" + tag,
		"newline in the salt":    head + salt[:10] + "\n" + salt[10:] + "$" + tag,
		"newline in the tag":     head + salt + "$" + tag + "\n",
		"url alphabet":           head + "3OPq8fj_Bg0UGyIpMDc-RQ" + "$" + tag,
		"salt one byte short":    head + short + "$" + tag,
		"salt one byte over":     head + long + "$" + tag,
		"tag one byte short":     head + salt + "$" + tag31,
		"tag one byte over":      head + salt + "$" + tag33,
		"five fields":            "$argon2id$v=19$m=19456,t=2,p=1$" + salt,
		"seven fields":           good + "$",
		"space before":           " " + good,
		"no leading separator":   good[1:],
	} {
		if _, err := s.decodeStored(in); !errors.Is(err, ErrStoredHash) {
			t.Errorf("%s: got %v, want ErrStoredHash", name, err)
		}
	}
}
