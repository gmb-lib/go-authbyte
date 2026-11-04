package apikeys

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPresentedHoldsAWellFormedKeyAsASecret(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	m, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.Presented(m.Key.Reveal())
	if err != nil {
		t.Fatalf("a minted key was refused: %v", err)
	}

	if got.Reveal() != m.Key.Reveal() {
		t.Fatal("the secret is not the key presented")
	}

	if printed := fmt.Sprint(got); printed != redacted {
		t.Fatalf("the presented key prints as %q", printed)
	}
}

// Every shape that can never be a key of the family is refused alike, before anything is derived or
// looked up: Presented has neither a lookup nor a derive to call.
func TestPresentedRefusesWhatCanNeverBeAKey(t *testing.T) {
	s, err := NewScheme(Config{Scheme: "tk"})
	if err != nil {
		t.Fatal(err)
	}

	m, err := s.Mint()
	if err != nil {
		t.Fatal(err)
	}

	key := m.Key.Reveal()
	other, err := NewScheme(Config{Scheme: "ok"})
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := other.Mint()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"empty":                                  "",
		"another scheme":                         otherKey.Key.Reveal(),
		"one short":                              key[:len(key)-1],
		"one long":                               key + "A",
		"a lookup character not in its alphabet": key[:3] + "U" + key[4:],
		"a secret character not in its alphabet": key[:len(key)-1] + "=",
		"the separators moved":                   strings.Replace(key, "_", "-", 1),
	}

	for name, k := range cases {
		got, err := s.Presented(k)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}

		if got.Reveal() != "" {
			t.Errorf("%s: a refused key was still held", name)
		}

		if k != "" && strings.Contains(err.Error(), k) {
			t.Errorf("%s: the refusal names the input", name)
		}
	}
}

func TestTheTokenTypeIsAnAbsoluteURI(t *testing.T) {
	if !strings.HasPrefix(TokenType, "urn:") {
		t.Fatalf("%q is not an absolute URI", TokenType)
	}
}
