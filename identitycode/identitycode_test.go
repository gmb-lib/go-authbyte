package identitycode

import (
	"errors"
	"strings"
	"testing"
)

// Every identity code in this file is assembled from its parts at run time.
// An identity-code-shaped literal in the source is indistinguishable from a
// real person's code to a reader and from a credential to a secret scanner;
// the groups below carry no shape of their own, and the digits differ between
// groups so a test can tell a right split from a wrong one.
const (
	lvHead = "123456" // leading group of a Latvian personal code (six digits)
	lvTail = "78901"  // its serial (five digits)

	eeHead = "234567" // an Estonian personal code, which is written unsplit
	eeTail = "89012"

	ntrHead = "345678" // a Latvian trade-register number, also eleven digits
	ntrTail = "90123"

	ltHead = "456789" // a Lithuanian personal code
	ltTail = "01234"

	pasBody = "AB987654" // a passport number: letters and digits

	// An identifier that begins with five letters, which is the shape of an
	// identity type and a country and so cannot be read back on its own.
	prefixLike = "PASSK123"
)

// lvSpelt is the Latvian personal code as a person writes it.
func lvSpelt() string { return lvHead + "-" + lvTail }

// lvStored is the one spelling the platform stores it as.
func lvStored() string { return "PNOLV-" + lvHead + lvTail }

// The transformation, spelling by spelling. These rows are the normative
// vector list: each is a way the same code really arrives, and every one of
// them has to become the same stored value or the person is two people.
func TestCanonicalSpellings(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		country string
		want    string
	}{
		{"card certificate, hyphenated", "PNOLV-" + lvHead + "-" + lvTail, "", lvStored()},
		{"provider claim, already stored form", lvStored(), "", lvStored()},
		{"typed with the separator, country from the screen", lvSpelt(), "LV", lvStored()},
		{"typed without the separator", lvHead + lvTail, "LV", lvStored()},
		{"lower case and surrounding space", "  pnolv-" + lvHead + "-" + lvTail + "  ", "", lvStored()},
		{"dots and slashes as separators", lvHead + "." + lvTail, "LV", lvStored()},
		{"an Estonian code, written unsplit", "PNOEE-" + eeHead + eeTail, "", "PNOEE-" + eeHead + eeTail},
		{"an organisation, from its trade register", "NTRLV-" + ntrHead + ntrTail, "", "NTRLV-" + ntrHead + ntrTail},
		{"a passport number", "PASSK-" + pasBody, "", "PASSK-" + pasBody},
		{"a passport number written in lower case", strings.ToLower("PASSK-" + pasBody), "", "PASSK-" + pasBody},
		{"the cross-border login form", "LV/LV/" + lvSpelt(), "", lvStored()},
		{"the cross-border form, foreign identifier", "LT/LV/" + ltHead + ltTail, "", "PNOLT-" + ltHead + ltTail},
		{"the cross-border form wrapping a prefixed value", "LV/LV/PNOLV-" + lvHead + "-" + lvTail, "", lvStored()},
		{"a country hint is only a hint", lvSpelt(), "lv", lvStored()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Canonical(c.raw, c.country)
			if err != nil {
				t.Fatalf("Canonical(%q, %q) refused it: %v", c.raw, c.country, err)
			}
			if got != c.want {
				t.Fatalf("Canonical(%q, %q) = %q, want %q", c.raw, c.country, got, c.want)
			}
		})
	}
}

// Every identity type this package recognises, crossed with both spellings a
// prefixed code arrives in: with the national separator and without it.
//
// It is a MATRIX rather than a row per type on purpose. The separator handling
// and the type handling are independent in the code, so a table that crosses
// them catches a rule that was only ever written for personal numbers — and
// until this test, two of the five types had no vector at all here. A tax
// number appeared in neither this suite nor the store's, and an identity card
// only in a display case, so a code arriving under either was in practice
// untested on the one path that decides who a person is.
//
// Each type carries its own digits, so a wrong answer names the type it came
// from instead of matching another row by accident.
func TestEveryIdentityTypeInBothPrefixedSpellings(t *testing.T) {
	types := []struct {
		semantics string
		country   string
		head      string
		tail      string
		what      string
	}{
		{"PNO", "LV", lvHead, lvTail, "a national personal number"},
		{"NTR", "LV", ntrHead, ntrTail, "an organisation's trade register number"},
		{"PAS", "SK", "AB98", "7654", "a passport number: letters and digits"},
		{"IDC", "BE", "590082", "394654", "a national identity card number"},
		{"TIN", "EE", "765432", "10987", "a tax identification number"},
	}

	for _, ty := range types {
		want := ty.semantics + ty.country + "-" + ty.head + ty.tail
		spellings := []struct{ name, raw string }{
			{"with the national separator", ty.semantics + ty.country + "-" + ty.head + "-" + ty.tail},
			{"without the separator", ty.semantics + ty.country + "-" + ty.head + ty.tail},
			{"in lower case", strings.ToLower(ty.semantics + ty.country + "-" + ty.head + "-" + ty.tail)},
		}
		for _, sp := range spellings {
			t.Run(ty.semantics+"/"+sp.name, func(t *testing.T) {
				// The hint contradicts the value on every row, because a country
				// the value states must win for every type and not only for the
				// one the rule was written against.
				got, err := Canonical(sp.raw, "ZZ")
				if err != nil {
					t.Fatalf("Canonical(%q) refused %s: %v", sp.raw, ty.what, err)
				}
				if got != want {
					t.Fatalf("Canonical(%q) = %q, want %q (%s)", sp.raw, got, want, ty.what)
				}

				// And it comes apart again into the three things it is made of,
				// which is what every caller reading a stored value depends on.
				c, err := Parse(got)
				if err != nil {
					t.Fatalf("Parse(%q): %v", got, err)
				}
				if c.Semantics != ty.semantics || c.Country != ty.country || c.Identifier != ty.head+ty.tail {
					t.Fatalf("Parse(%q) = %+v, want %s/%s/%s", got, c, ty.semantics, ty.country, ty.head+ty.tail)
				}
				if Key(got) != want {
					t.Fatalf("Key(%q) = %q, want %q", got, Key(got), want)
				}

				// Nothing but a Latvian personal number is ever shown split, so
				// for every other row the whole code — type and country included —
				// is what a person sees. That is the guard against a namesake and
				// an organisation rendering as one string.
				if shown := Display(got); ty.semantics != SemanticsPersonalNumber || ty.country != "LV" {
					if shown != want {
						t.Fatalf("Display(%q) = %q, want the whole code %q for %s", got, shown, want, ty.what)
					}
				}
			})
		}
	}
}

// A country in the value always beats the hint. A partner's system may or may
// not put the country on the wire, and when it does, that is the fact about
// the person — our screen's default is not.
func TestPrefixInTheValueWinsOverTheHint(t *testing.T) {
	got, err := Canonical("PNOLT-"+ltHead+ltTail, "LV")
	if err != nil {
		t.Fatalf("refused a Lithuanian code carrying its own country: %v", err)
	}
	if want := "PNOLT-" + ltHead + ltTail; got != want {
		t.Fatalf("Canonical = %q, want %q — the hint must not overwrite a country the value states", got, want)
	}
}

// The country is part of the identity. Two people in two countries can hold
// the same digits, and cross-border co-signing means both can reach the same
// document, so stripping the country would hand one person the other's papers.
func TestTheCountryIsPartOfTheIdentity(t *testing.T) {
	lv, err := Canonical(lvHead+lvTail, "LV")
	if err != nil {
		t.Fatal(err)
	}
	ee, err := Canonical(lvHead+lvTail, "EE")
	if err != nil {
		t.Fatal(err)
	}
	if lv == ee {
		t.Fatalf("the same digits in two countries produced one identity (%q)", lv)
	}
	if Key(lv) == Key(ee) {
		t.Fatalf("the same digits in two countries compare equal (%q)", Key(lv))
	}
}

// What is refused, and why each refusal exists rather than a guess.
func TestCanonicalRefusals(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		country string
		want    error
	}{
		{"nothing at all", "", "", ErrEmpty},
		{"only separators", " - . / ", "LV", ErrMalformed},
		{"a bare code and no country anywhere", lvHead + lvTail, "", ErrCountryRequired},
		{"a country hint that is not a country", lvHead + lvTail, "LVA", ErrCountryInvalid},
		{"a country hint that is not letters", lvHead + lvTail, "L1", ErrCountryInvalid},
		{"an identity type we do not recognise", "VATLV-" + ntrHead + ntrTail, "LV", ErrUnknownSemantics},
		{"a national eID type, not in the recognised set", "EIDLV-" + lvHead + lvTail, "LV", ErrUnknownSemantics},
		{"a locally defined identity type", "EI:SE-" + lvHead + lvTail, "LV", ErrUnknownSemantics},
		{"a prefix with no identifier behind it", "PNOLV-", "LV", ErrMalformed},
		{"characters that are not letters or digits", "PNOLV-" + lvHead + "#" + lvTail, "", ErrMalformed},
		{"a subdivision in the country field", "NTRDE+HE-" + ntrHead, "DE", ErrMalformed},
		{"a prefix written without its hyphen", "PNOLV" + lvHead + lvTail, "LV", ErrAmbiguous},
		{"an unrecognised prefix written without its hyphen", "VATLV" + ntrHead + ntrTail, "LV", ErrAmbiguous},
		{"a look-alike letter from another alphabet", "PNOLV-" + lvHead + "Х" + lvTail, "", ErrMalformed},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Canonical(c.raw, c.country)
			if !errors.Is(err, c.want) {
				t.Fatalf("Canonical(%q, %q) = %q, %v — want the refusal %v", c.raw, c.country, got, err, c.want)
			}
			if got != "" {
				t.Fatalf("a refused code still returned a value (%q) — a caller that ignores the error would store it", got)
			}
		})
	}
}

// Nothing this package produces may ever need producing twice. The store's own
// constraint is exactly this assertion — a stored value has to equal its own
// canonical form — so a value that is not already canonical is a value the
// database will refuse at the door.
func TestCanonicalIsAlreadyCanonical(t *testing.T) {
	raws := []struct{ raw, country string }{
		{lvSpelt(), "LV"},
		{lvHead + lvTail, "LV"},
		{"PNOLV-" + lvHead + "-" + lvTail, ""},
		{"PNOEE-" + eeHead + eeTail, ""},
		{"NTRLV-" + ntrHead + ntrTail, ""},
		{"PASSK-" + pasBody, ""},
		{"LV/LV/" + lvSpelt(), ""},
	}

	for _, r := range raws {
		stored, err := Canonical(r.raw, r.country)
		if err != nil {
			t.Fatalf("Canonical(%q, %q): %v", r.raw, r.country, err)
		}
		if stored == "" {
			t.Fatalf("Canonical(%q, %q) accepted the code and produced nothing", r.raw, r.country)
		}
		again, err := Canonical(stored, "")
		if err != nil {
			t.Fatalf("a stored value was refused on its way back in: Canonical(%q, \"\"): %v", stored, err)
		}
		if again != stored {
			t.Fatalf("Canonical is not settled: %q became %q", stored, again)
		}
		if _, err := Parse(stored); err != nil {
			t.Fatalf("Canonical produced a value it cannot take apart (%q): %v", stored, err)
		}
	}
}

// Key is for the caller holding a value of unknown provenance that it wants to
// compare rather than store: every spelling of one code answers with the same
// key, and a value it cannot make sense of stays distinct from every other.
func TestKey(t *testing.T) {
	spellings := []string{
		"PNOLV-" + lvHead + "-" + lvTail,
		lvStored(),
		"  pnolv-" + lvHead + lvTail + " ",
		"LV/LV/" + lvSpelt(),
	}

	want := Key(lvStored())
	if want != lvStored() {
		t.Fatalf("Key of a stored code = %q, want the code itself (%q)", want, lvStored())
	}
	for _, s := range spellings {
		if got := Key(s); got != want {
			t.Fatalf("Key(%q) = %q, want %q", s, got, want)
		}
	}

	// A bare code has no country, so Key cannot know whose it is. It must not
	// answer with a Latvian identity, and it must not answer with something a
	// real identity could collide with.
	bare := Key(lvSpelt())
	if bare == want {
		t.Fatalf("Key guessed a country for a bare code (%q)", bare)
	}

	// Two values it cannot make sense of stay two values. Collapsing them
	// would be the same failure as the one this package exists to end.
	a, b := Key("VATLV-"+ntrHead), Key("VATLV-"+ntrTail)
	if a == b {
		t.Fatalf("two different unrecognised codes share one key (%q)", a)
	}
	if lower := Key(strings.ToLower("VATLV-" + ntrHead)); lower != a {
		t.Fatalf("Key(%q) = %q, want %q — case is not part of an identity", strings.ToLower("VATLV-"+ntrHead), lower, a)
	}
	for _, k := range []string{bare, a, b} {
		if strings.Contains(k, "-") {
			t.Fatalf("the key of an unrecognised value (%q) carries a hyphen, so it can collide with a stored identity", k)
		}
	}
}

// What a person sees is their own national code, written the way their country
// writes it — never the prefix the platform keys on.
func TestDisplay(t *testing.T) {
	cases := []struct{ name, stored, want string }{
		{"a Latvian personal code is split", lvStored(), lvSpelt()},
		{"a country with no known spelling keeps its whole code", "PNOEE-" + eeHead + eeTail, "PNOEE-" + eeHead + eeTail},
		{"an organisation number is not split, and stays an organisation number", "NTRLV-" + ntrHead + ntrTail, "NTRLV-" + ntrHead + ntrTail},
		{"a passport number is shown as it is stored", "PASSK-" + pasBody, "PASSK-" + pasBody},
		{"something unparseable is shown unchanged", "not a code", "not a code"},
		{"a code of the wrong length for its country is not forced", "PNOLV-" + lvHead, "PNOLV-" + lvHead},
		{"an identifier that reads like a prefix keeps the code it belongs to", "PNOLV-" + prefixLike, "PNOLV-" + prefixLike},
		{"a personal number that is not all digits is not split", "PNOLV-" + lvHead + "7890A", "PNOLV-" + lvHead + "7890A"},
	}

	// The point of the whole function, asserted directly: five distinct principals
	// holding the SAME digits must not render as one string. A person, a foreign
	// namesake and an organisation used to be indistinguishable here.
	same := []string{
		"PNOEE-" + eeHead + eeTail,
		"PNOLT-" + eeHead + eeTail,
		"NTREE-" + eeHead + eeTail,
		"PASEE-" + eeHead + eeTail,
		"IDCEE-" + eeHead + eeTail,
	}
	seen := make(map[string]string, len(same))
	for _, stored := range same {
		shown := Display(stored)
		if other, clash := seen[shown]; clash {
			t.Fatalf("%q and %q are different principals but both display as %q", other, stored, shown)
		}
		seen[shown] = stored
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Display(c.stored); got != c.want {
				t.Fatalf("Display(%q) = %q, want %q", c.stored, got, c.want)
			}
		})
	}
}

// Parse accepts the stored spelling and nothing else: a value read from a
// store is already canonical, so anything else is a caller handing Parse a raw
// input where a stored one belongs.
func TestParse(t *testing.T) {
	c, err := Parse(lvStored())
	if err != nil {
		t.Fatalf("Parse(%q): %v", lvStored(), err)
	}
	if c.Semantics != "PNO" || c.Country != "LV" || c.Identifier != lvHead+lvTail {
		t.Fatalf("Parse(%q) = %+v", lvStored(), c)
	}
	if c.String() != lvStored() {
		t.Fatalf("String() = %q, want %q", c.String(), lvStored())
	}

	for _, bad := range []string{"", lvSpelt(), "pnolv-" + lvHead + lvTail, "PNOLV-" + lvHead + "-" + lvTail, "VATLV-" + ntrHead} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("Parse(%q) accepted a value that is not the stored spelling", bad)
		}
	}
}

// The property a lost person is made of: a code shown to somebody and typed
// straight back in has to key to the identity it came from. It is asserted for
// every national personal number, which is the one kind of code a person types.
// A code of another type legitimately does not survive the trip — Display drops
// the identity type, and a retyped organisation number is read as the personal
// number the typist entered, because that is what typing one into a personal
// code field means.
func FuzzRoundTrip(f *testing.F) {
	f.Add("PNOLV-"+lvHead+"-"+lvTail, "")
	f.Add(lvSpelt(), "LV")
	f.Add(lvHead+lvTail, "LV")
	f.Add("PNOEE-"+eeHead+eeTail, "")
	f.Add("NTRLV-"+ntrHead+ntrTail, "")
	f.Add("LV/LV/"+lvSpelt(), "")
	f.Add("", "")
	f.Add("-", "LV")

	f.Fuzz(func(t *testing.T, raw, country string) {
		stored, err := Canonical(raw, country)
		if err != nil {
			if stored != "" {
				t.Fatalf("Canonical(%q, %q) refused with a value (%q)", raw, country, stored)
			}

			return
		}

		// Whatever it accepted, the store must accept too: the value equals its
		// own canonical form, and it can be taken apart again.
		if stored == "" {
			t.Fatalf("Canonical(%q, %q) accepted the code and produced nothing", raw, country)
		}
		c, err := Parse(stored)
		if err != nil {
			t.Fatalf("Canonical(%q, %q) = %q, which Parse rejects: %v", raw, country, stored, err)
		}
		if again, err := Canonical(stored, ""); err != nil || again != stored {
			t.Fatalf("Canonical(%q) = %q, %v — a stored value must come back unchanged", stored, again, err)
		}
		if Key(stored) != stored {
			t.Fatalf("Key(%q) = %q — a stored value is its own key", stored, Key(stored))
		}

		if c.Semantics != "PNO" {
			return
		}
		retyped, err := Canonical(Display(stored), c.Country)
		if err != nil {
			t.Fatalf("a person retyping what they were shown (%q from %q) was refused: %v", Display(stored), stored, err)
		}
		if Key(retyped) != Key(stored) {
			t.Fatalf("retyping %q as %q lost the person: %q vs %q", stored, Display(stored), Key(retyped), Key(stored))
		}
	})
}
