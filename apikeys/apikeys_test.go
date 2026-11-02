package apikeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// mutateSecret returns key with its last secret character swapped for another valid one.
func mutateSecret(t *testing.T, s *Scheme, key string) string {
	t.Helper()

	last := key[len(key)-1]
	repl := byte('A')

	if last == 'A' {
		repl = 'B'
	}

	out := key[:len(key)-1] + string(repl)
	if _, err := s.parse(out); err != nil {
		t.Fatalf("mutated key no longer parses: %v", err)
	}

	return out
}

func TestMintedKeyVerifies(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}

	k, err := s.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	key := k.Key.Reveal()

	if len(key) != len("tk")+1+lookupLen+1+secretLen {
		t.Fatalf("key is %d characters", len(key))
	}

	if !strings.HasPrefix(key, "tk_"+k.Lookup+"_") {
		t.Fatal("the key does not start with the scheme and its lookup part")
	}

	for _, r := range k.Lookup {
		if !strings.ContainsRune(crockford, r) {
			t.Fatalf("lookup part holds %q, outside the alphabet", r)
		}
	}

	st, err := s.decodeStored(k.Hash)
	if err != nil {
		t.Fatalf("the stored string does not decode: %v", err)
	}

	if st.params != DefaultParams() || len(st.salt) != saltLen || len(st.tag) != tagLen {
		t.Fatalf("stored at %+v with a %d-byte salt and a %d-byte tag", st.params, len(st.salt), len(st.tag))
	}

	store := newMemStore()
	store.put(k)

	v, err := s.NewVerifier(store.lookup, VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	res, err := v.Verify(context.Background(), "caller", key)
	if err != nil {
		t.Fatalf("Verify with real argon2id: %v", err)
	}

	if res.Lookup != k.Lookup {
		t.Fatalf("result names %q, want %q", res.Lookup, k.Lookup)
	}

	if _, err := v.Verify(context.Background(), "caller", mutateSecret(t, s, key)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a wrong secret with real argon2id: got %v, want ErrInvalid", err)
	}
}

func TestMintTwiceSharesNothing(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	s.derive = (&countingDerive{}).derive

	a, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}

	b, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}

	pa, _ := s.parse(a.Key.Reveal())
	pb, _ := s.parse(b.Key.Reveal())

	if a.Lookup == b.Lookup || bytes.Equal(pa.secret, pb.secret) {
		t.Fatal("two minted keys share a lookup part or a secret")
	}

	sa, _ := s.decodeStored(a.Hash)
	sb, _ := s.decodeStored(b.Hash)

	if bytes.Equal(sa.salt, sb.salt) {
		t.Fatal("two minted keys share a salt")
	}
}

func TestMintRefusesWhenRandomnessFails(t *testing.T) {
	for _, n := range []int{0, lookupBytes, lookupBytes + secretBytes, lookupBytes + secretBytes + saltLen - 1} {
		s, err := NewScheme(Config{Scheme: "tk"})
		if err != nil {
			t.Fatal(err)
		}

		s.rand = bytes.NewReader(make([]byte, n))

		k, err := s.Mint()
		if err == nil {
			t.Fatalf("%d bytes of randomness: a key was minted", n)
		}

		if k.Key.Reveal() != "" || k.Lookup != "" || k.Hash != "" {
			t.Fatalf("%d bytes of randomness: a refused mint still returned parts of a key", n)
		}
	}
}

func TestMintedKeyHidesItsSecretWhenPrinted(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	s.derive = (&countingDerive{}).derive

	k, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}

	key := k.Key.Reveal()
	secret := key[len(key)-secretLen:]

	js, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	for name, out := range map[string]string{
		"%v":       fmt.Sprintf("%v", k),
		"%+v":      fmt.Sprintf("%+v", k),
		"%#v":      fmt.Sprintf("%#v", k),
		"%s key":   fmt.Sprintf("%s", k.Key),
		"%q key":   fmt.Sprintf("%q", k.Key),
		"%x key":   fmt.Sprintf("%x", k.Key),
		"String":   k.Key.String(),
		"JSON":     string(js),
		"%v key":   fmt.Sprintf("%v", k.Key),
		"%#v key":  fmt.Sprintf("%#v", k.Key),
		"Sprint":   fmt.Sprint(k.Key),
		"Sprintln": fmt.Sprintln(k),
	} {
		if strings.Contains(out, secret) || strings.Contains(out, fmt.Sprintf("%x", key)) {
			t.Errorf("%s shows the secret: %s", name, out)
		}
	}

	if !strings.Contains(fmt.Sprintf("%+v", k), k.Lookup) {
		t.Error("printing with field names hides the lookup part, which is public")
	}
}

func TestSchemeNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"":          false,
		"v":         false,
		"vk":        true,
		"fb2":       true,
		"abcdefgh":  true,
		"abcdefghi": false,
		"v_k":       false,
		"Vk":        false,
		"1k":        false,
		"v-k":       false,
		"vk ":       false,
	} {
		s, err := NewScheme(Config{Scheme: name})
		if ok && err != nil {
			t.Errorf("%q refused: %v", name, err)
		}

		if !ok && (err == nil || s != nil) {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestSchemeParametersAreChecked(t *testing.T) {
	d := DefaultParams()

	for name, c := range map[string]Config{
		"zero memory":              {Scheme: "tk", Params: Params{0, d.Iterations, d.Parallelism}},
		"zero iterations":          {Scheme: "tk", Params: Params{d.Memory, 0, d.Parallelism}},
		"zero parallelism":         {Scheme: "tk", Params: Params{d.Memory, d.Iterations, 0}},
		"minted below the floor":   {Scheme: "tk", Params: d, Floor: Params{d.Memory + 1, d.Iterations, d.Parallelism}},
		"ceiling below the minted": {Scheme: "tk", Params: d, Ceiling: Params{d.Memory - 1, d.Iterations, d.Parallelism}},
		"zero in the floor":        {Scheme: "tk", Params: d, Floor: Params{d.Memory, 0, d.Parallelism}},
		"memory one KiB short":     {Scheme: "tk", Params: Params{d.Memory - 1, d.Iterations, d.Parallelism}},
		"memory typed as MiB":      {Scheme: "tk", Params: Params{19, d.Iterations, d.Parallelism}},
		"one pass short":           {Scheme: "tk", Params: Params{d.Memory * 2, d.Iterations - 1, d.Parallelism}},
		"floor one KiB short":      {Scheme: "tk", Params: d, Floor: Params{d.Memory - 1, d.Iterations, d.Parallelism}},
		"floor one pass short":     {Scheme: "tk", Params: d, Floor: Params{d.Memory, d.Iterations - 1, d.Parallelism}},
		"both one KiB short":       {Scheme: "tk", Params: Params{d.Memory - 1, d.Iterations, d.Parallelism}, Floor: Params{d.Memory - 1, d.Iterations, d.Parallelism}},
		"both one pass short":      {Scheme: "tk", Params: Params{d.Memory, d.Iterations - 1, d.Parallelism}, Floor: Params{d.Memory, d.Iterations - 1, d.Parallelism}},
	} {
		s, err := NewScheme(c)
		if err == nil || s != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseKeepsTheSeparatorInsideTheSecret(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "vk"})
	if err != nil {
		t.Fatal(err)
	}

	lookup := "24C1Y9HD"

	for _, secret := range []string{
		strings.Repeat("_", secretLen),
		"_" + strings.Repeat("A", secretLen-1),
		strings.Repeat("A", secretLen-1) + "_",
		strings.Repeat("a-", secretLen/2),
	} {
		pk, err := s.parse("vk_" + lookup + "_" + secret)
		if err != nil {
			t.Fatalf("secret %q refused: %v", secret, err)
		}

		if pk.lookup != lookup || string(pk.secret) != secret {
			t.Fatalf("parsed %q / %q, want %q / %q", pk.lookup, pk.secret, lookup, secret)
		}
	}
}

func TestParseRefusesEachMalformedField(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "vk"})
	if err != nil {
		t.Fatal(err)
	}

	lookup := "24C1Y9HD"
	secret := strings.Repeat("Ab3-", secretLen/4)
	good := "vk_" + lookup + "_" + secret

	if _, err := s.parse(good); err != nil {
		t.Fatalf("the well-formed key is refused: %v", err)
	}

	for name, key := range map[string]string{
		"empty":                      "",
		"scheme only":                "vk",
		"another scheme":             "sk_" + lookup + "_" + secret,
		"scheme in upper case":       "VK_" + lookup + "_" + secret,
		"no separator after":         "vk" + lookup + "_" + secret + "A",
		"no separator before":        "vk_" + lookup + "A" + secret,
		"lookup one short":           "vk_" + lookup[:7] + "_" + secret + "A",
		"lookup one long":            "vk_" + lookup + "A_" + secret[1:],
		"lookup in lower case":       "vk_" + strings.ToLower(lookup) + "_" + secret,
		"lookup holds I":             "vk_24C1Y9HI_" + secret,
		"lookup holds L":             "vk_24C1Y9HL_" + secret,
		"lookup holds O":             "vk_24C1Y9HO_" + secret,
		"lookup holds U":             "vk_24C1Y9HU_" + secret,
		"secret one short":           "vk_" + lookup + "_" + secret[1:],
		"secret one long":            good + "A",
		"secret holds +":             "vk_" + lookup + "_" + secret[1:] + "+",
		"secret holds =":             "vk_" + lookup + "_" + secret[1:] + "=",
		"secret holds .":             "vk_" + lookup + "_" + secret[1:] + ".",
		"secret holds NUL":           "vk_" + lookup + "_" + secret[1:] + "\x00",
		"secret holds a 2-byte rune": "vk_" + lookup + "_" + secret[2:] + "é",
		"empty secret":               "vk_" + lookup + "_",
		"space before":               " " + good,
		"space after":                good + " ",
		"newline after":              good + "\n",
	} {
		_, err := s.parse(key)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)

			continue
		}

		if msg := err.Error(); strings.Contains(msg, lookup) || strings.Contains(msg, secret[4:12]) {
			t.Errorf("%s: the error repeats the input: %s", name, msg)
		}
	}
}

func TestDefaultsAreUsable(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatalf("NewScheme with defaults: %v", err)
	}

	if s.floor != DefaultParams() || s.mint != DefaultParams() {
		t.Fatalf("defaults: minted %+v, floor %+v; want both %+v", s.mint, s.floor, DefaultParams())
	}

	v, err := s.NewVerifier(newMemStore().lookup, VerifierConfig{})
	if err != nil {
		t.Fatalf("NewVerifier with defaults: %v", err)
	}

	if cap(v.slots) != DefaultMaxDerives || v.busyAfter <= 0 || v.busyAfter > time.Minute {
		t.Fatalf("default cap %d and busy delay %v", cap(v.slots), v.busyAfter)
	}
}

func TestNewVerifierNeedsALookup(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	if v, err := s.NewVerifier(nil, VerifierConfig{}); err == nil || v != nil {
		t.Fatal("a verifier was built with no way to look keys up")
	}

	if v, err := s.NewVerifier(newMemStore().lookup, VerifierConfig{MaxDerives: -1}); err == nil || v != nil {
		t.Fatal("a verifier was built with a negative derive cap")
	}
}
