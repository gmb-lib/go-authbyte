package apikeys

import (
	"errors"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	s, err := NewScheme(Config{Scheme: "vk"})
	if err != nil {
		f.Fatal(err)
	}

	for _, seed := range []string{
		"vk_24C1Y9HD_" + strings.Repeat("Ab3-", secretLen/4),
		"vk_ZZZZZZZZ_" + strings.Repeat("_", secretLen),
		"vk_24C1Y9HD_",
		"",
		"vk",
		"vk__",
		strings.Repeat("_", 44),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		pk, err := s.parse(in)
		if err != nil {
			if !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
				t.Fatalf("refusal is not the one fixed error: %v", err)
			}

			return
		}

		if "vk_"+pk.lookup+"_"+string(pk.secret) != in {
			t.Fatalf("accepted %q but its parts rebuild %q", in, "vk_"+pk.lookup+"_"+string(pk.secret))
		}
	})
}

func FuzzDecodeStored(f *testing.F) {
	s, err := NewScheme(Config{Scheme: "vk"})
	if err != nil {
		f.Fatal(err)
	}

	for _, vec := range existingFormatVectors {
		f.Add(vec.stored)
	}

	for _, seed := range []string{"", "$", "$argon2id$v=19$m=0,t=0,p=0$$", "$argon2id$v=19$m=19456,t=2,p=1$A$A"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		st, err := s.decodeStored(in)
		if err != nil {
			if !errors.Is(err, ErrStoredHash) {
				t.Fatalf("refusal is not ErrStoredHash: %v", err)
			}

			return
		}

		// Whatever is accepted is in its one canonical spelling, inside the bounds.
		if got := encodeStored(st.params, st.salt, st.tag); got != in {
			t.Fatalf("accepted %q, which re-encodes as %q", in, got)
		}

		if !st.params.atLeast(s.floor) || !s.ceiling.atLeast(st.params) {
			t.Fatalf("accepted parameters %+v outside %+v..%+v", st.params, s.floor, s.ceiling)
		}
	})
}
