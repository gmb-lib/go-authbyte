// Package identitycode turns the many spellings of a person's or an
// organisation's identity code into the one form the platform stores, compares
// and shows.
//
// The same signatory's code reaches a service written several ways. From a card
// certificate or an identity provider it carries the identity type and the
// country ("PNOLV-123456-78901"). A person typing it into a form writes only
// their national code, with or without its separator. A partner's system may
// send either. Compared character by character those are four different people,
// and the one who signed a document under one spelling cannot find it under
// another. This package collapses them to a single stored spelling — the
// identity type, the country, a hyphen, and the national code with its
// separators removed — so identity can be compared with plain equality
// wherever it is stored.
//
// The country is never guessed. A country already carried in the value always
// wins; the caller's hint is consulted only when the value carries none, and a
// bare code with no country available is refused rather than filed under a
// guess, because a wrong identity key is the wrong person's documents.
package identitycode

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

// The refusals. Each one is a case where storing anything at all would mean
// storing a guess, and a mis-keyed code silently becomes a second person — so
// the caller is refused instead, loudly, at the door.
//
// None of them carries the offending value: an identity code is personal data
// and these errors are written to service logs.
var (
	// ErrEmpty is returned when there is no code to canonicalise.
	ErrEmpty = errors.New("identitycode: no code given")

	// ErrCountryRequired is returned for a code that names no country of its
	// own when the caller knows of none either. There is no default: a bare
	// code is not Latvian because most of them are.
	ErrCountryRequired = errors.New("identitycode: the code names no country and none was supplied")

	// ErrCountryInvalid is returned when the supplied country is not a
	// two-letter country code.
	ErrCountryInvalid = errors.New("identitycode: the supplied country is not a two-letter country code")

	// ErrUnknownSemantics is returned for a code whose identity type this
	// package does not recognise. Admitting one is a change here, not a guess
	// at the call site.
	ErrUnknownSemantics = errors.New("identitycode: unrecognised identity type")

	// ErrAmbiguous is returned for a code with no identity type of its own
	// that begins like one, which cannot be told apart from a code that has
	// one.
	ErrAmbiguous = errors.New("identitycode: the code begins like an identity type but carries none")

	// ErrMalformed is returned when nothing is left of the identifier once its
	// separators are removed, or when it is written in characters an identity
	// code is not written in.
	ErrMalformed = errors.New("identitycode: the identifier is empty or not written in letters and digits")
)

// SemanticsPersonalNumber is the identity type of a national personal number —
// a civic registration number. It is the type given to a code that arrives
// with none of its own, because a code typed into a personal-code field is a
// personal number.
const SemanticsPersonalNumber = "PNO"

// The identity types this package recognises, from the standard semantics for
// the serial number of a signing certificate: a national personal number, a
// national trade-register number (organisations, and the electronic seals they
// sign with), a passport number, a national identity card number and a tax
// identification number.
//
// The set is deliberately data. Recognising a further type is one entry here
// and one release — never a decision taken at a call site, because a type this
// package does not know is refused rather than keyed as something else.
var recognisedSemantics = map[string]struct{}{
	"PNO": {},
	"NTR": {},
	"PAS": {},
	"IDC": {},
	"TIN": {},
}

var (
	// prefixedForm is a code that names its own identity type and country:
	// three letters, two letters, the hyphen the standard puts there, then the
	// identifier. The hyphen is required — without it there is no telling a
	// prefix from an identifier that happens to start with letters, and
	// guessing is how one person becomes two.
	prefixedForm = regexp.MustCompile(`^([A-Za-z]{3})([A-Za-z]{2})-(.*)$`)

	// localPrefixedForm is a nationally defined identity type: two letters and
	// a colon, then the country. This package recognises none of them, so the
	// shape exists here only to be refused as a prefix rather than mistaken
	// for an identifier.
	localPrefixedForm = regexp.MustCompile(`^[A-Za-z]{2}:[A-Za-z]{2}-`)

	// crossBorderForm is the shape a code takes when it crosses a border in a
	// login: the country of the code, the country that asked for it, and the
	// code itself.
	crossBorderForm = regexp.MustCompile(`^([A-Za-z]{2})/([A-Za-z]{2})/(.+)$`)

	// storedForm is the stored spelling, exactly. It is the shape the store's
	// own constraint requires, written here so that the two agree by
	// construction rather than by memory.
	storedForm = regexp.MustCompile(`^([A-Z]{3})([A-Z]{2})-([A-Z0-9]+)$`)
)

// Canonical returns the one spelling of raw that is stored and compared: the
// identity type, the country, a hyphen, and the identifier with every space,
// hyphen, dot and slash removed, upper-cased.
//
// country is consulted only when raw names no country of its own — it is the
// country chosen on the screen the code was typed into, the country in the
// signing certificate, the country recorded for the system that sent it. Give
// it as a two-letter country code, or empty when no country is known. A
// country in the value always wins, and one that contradicts the hint is not
// an error: a partner's system may or may not put the country on the wire, and
// both have to be right.
//
// Every result satisfies Parse, and canonicalising it again returns it
// unchanged — which is what the store requires of the values it holds.
func Canonical(raw, country string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", ErrEmpty
	}

	// A cross-border code can arrive wrapped more than once. Each pass strips
	// one country pair, so the value shortens every time and the loop ends.
	// The leading country is the one that belongs to the code; the second says
	// only who asked for it, which is nothing about the person.
	for {
		m := crossBorderForm.FindStringSubmatch(v)
		if m == nil {
			break
		}
		country, v = m[1], strings.TrimSpace(m[3])
	}

	if m := prefixedForm.FindStringSubmatch(v); m != nil {
		semantics := asciiUpper(m[1])
		if _, ok := recognisedSemantics[semantics]; !ok {
			return "", ErrUnknownSemantics
		}
		id, err := identifier(m[3])
		if err != nil {
			return "", err
		}

		return semantics + asciiUpper(m[2]) + "-" + id, nil
	}

	if localPrefixedForm.MatchString(v) {
		return "", ErrUnknownSemantics
	}

	cc, err := countryCode(country)
	if err != nil {
		return "", err
	}
	id, err := identifier(v)
	if err != nil {
		return "", err
	}
	if beginsLikeAPrefix(id) {
		return "", ErrAmbiguous
	}

	return SemanticsPersonalNumber + cc + "-" + id, nil
}

// Key returns the value to compare two identity codes by. A stored code is
// already canonical, so its key is itself; Key is for the caller holding a
// value of unknown provenance that it wants to compare rather than store.
//
// It never fails and never guesses a country. A value it cannot make sense of
// comes back with its separators removed and its ASCII letters upper-cased,
// which keeps two different unrecognised values different — and keeps neither
// equal to any stored identity, since every stored value carries a hyphen and
// no fallback key does. Storing always goes through Canonical.
func Key(stored string) string {
	v := strings.TrimSpace(stored)
	if c, err := Parse(v); err == nil {
		return c.String()
	}
	if s, err := Canonical(v, ""); err == nil {
		return s
	}

	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case isSeparator(r):
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

// Display returns the spelling to show a person: their own national code,
// written the way their country writes it where that is known, and otherwise
// the code exactly as it is stored.
//
// THE COUNTRY IS NEVER DROPPED, and neither is the identity type. Where a
// country's own way of writing the number is known, that spelling identifies it
// on its own — "123456-78901" reads as a personal number to a Latvian and to
// nobody else. Everywhere else there is no such spelling to fall back on, and a
// bare identifier would render a person, a foreign namesake holding the same
// digits, and an organisation's register number as one identical string. Two of
// those are different people, and a screen that renders them alike asks somebody
// to approve a counterparty they cannot tell apart.
//
// Showing the stored code also keeps a property the fuzz test enforces: what a
// person is SHOWN can be typed back in and reaches that same person. A form that
// merely prefixed the country would not — the canonicaliser reads a space or a
// hyphen as a separator, so the country letters would be absorbed into the
// identifier and resolve to a different key, silently.
//
// A code Display cannot take apart is returned unchanged: a display is cosmetic,
// and seeing the raw value serves a person better than seeing nothing.
func Display(stored string) string {
	c, err := Parse(strings.TrimSpace(stored))
	if err != nil {
		return stored
	}
	if c.Semantics == SemanticsPersonalNumber {
		if split, ok := nationalSplits[c.Country]; ok {
			if s, ok := split(c.Identifier); ok {
				return s
			}
		}
	}

	// An identifier that itself opens like an identity type needs no guard here:
	// the fallback IS the whole code, and a national split applies only to an
	// all-digit identifier, which cannot open with five letters.
	return c.String()
}

// nationalSplits writes a national personal number the way its own country
// writes it. Only a country whose separator placement is known appears here;
// everywhere else Display shows the whole stored code instead, so the country and
// the type are present either way. An entry here is cosmetic — nothing compares a
// displayed value, so a wrong split is a wrong label. Leaving the country out of
// the fallback would NOT have been cosmetic, which is why the fallback is the
// stored code and not the bare identifier.
var nationalSplits = map[string]func(string) (string, bool){
	// Latvia writes a personal number as six digits, a hyphen and five. The
	// leading group was once a date of birth and since 2017 need not be, so
	// the split is on length alone and never on what the digits mean.
	"LV": func(id string) (string, bool) {
		const head = 6
		if len(id) != 11 || !isASCIIDigits(id) {
			return "", false
		}

		return id[:head] + "-" + id[head:], true
	},
}

// Code is an identity code taken apart: what kind of identifier it is, the
// country whose register issued it, and the identifier itself.
type Code struct {
	// Semantics is the identity type, e.g. "PNO" for a national personal
	// number.
	Semantics string
	// Country is the two-letter code of the country whose register issued the
	// identifier. It is part of the identity: the same digits in two countries
	// belong to two people.
	Country string
	// Identifier is the code itself, separators removed and upper-cased.
	Identifier string
}

// String returns the canonical stored spelling.
func (c Code) String() string {
	return c.Semantics + c.Country + "-" + c.Identifier
}

// Parse takes a stored identity code apart. It accepts the stored spelling and
// nothing else: a value read from a store is already canonical, so anything
// else is a raw input handed to Parse where a stored one belongs — and that
// belongs in Canonical.
func Parse(stored string) (Code, error) {
	m := storedForm.FindStringSubmatch(stored)
	if m == nil {
		return Code{}, ErrMalformed
	}
	if _, ok := recognisedSemantics[m[1]]; !ok {
		return Code{}, ErrUnknownSemantics
	}

	return Code{Semantics: m[1], Country: m[2], Identifier: m[3]}, nil
}

// identifier reduces the part after the identity type to the form that is
// stored: separators gone, letters upper-cased.
//
// Only the ASCII letters and digits survive. An identity code is written in
// them, and a letter from another alphabet that merely looks like one must not
// be able to pass as it — nor to become it, which is why the case folding here
// is ASCII-only rather than the language-aware kind.
func identifier(part string) (string, error) {
	var b strings.Builder
	b.Grow(len(part))
	for _, r := range part {
		switch {
		case isSeparator(r):
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		default:
			return "", ErrMalformed
		}
	}
	if b.Len() == 0 {
		return "", ErrMalformed
	}

	return b.String(), nil
}

// countryCode reads the caller's country hint.
func countryCode(hint string) (string, error) {
	h := strings.TrimSpace(hint)
	if h == "" {
		return "", ErrCountryRequired
	}
	if len(h) != 2 || !isASCIILetters(h) {
		return "", ErrCountryInvalid
	}

	return asciiUpper(h), nil
}

// beginsLikeAPrefix reports whether an identifier opens with the five letters
// that an identity type and a country are written in. Such a value cannot be
// told from a code that names its own type, so it is neither stored under a
// guess nor shown to a person on its own.
func beginsLikeAPrefix(id string) bool {
	const prefixLen = 5

	return len(id) >= prefixLen && isASCIILetters(id[:prefixLen])
}

// isSeparator reports whether a character is one of the separators an identity
// code is written with rather than part of the code: any space, and the hyphen,
// dot and slash that different systems put between its groups.
func isSeparator(r rune) bool {
	return unicode.IsSpace(r) || r == '-' || r == '.' || r == '/'
}

func isASCIILetters(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}

	return len(s) > 0
}

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return len(s) > 0
}

// asciiUpper upper-cases the ASCII letters in s and leaves everything else
// alone. It is deliberately not the language-aware fold: the store applies the
// same transformation in SQL, and the two only agree for as long as both stay
// inside the ASCII alphabet.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}

	return string(b)
}
