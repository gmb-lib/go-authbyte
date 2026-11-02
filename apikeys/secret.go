package apikeys

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[redacted]"

// Secret is a whole key. It prints, marshals and logs as a fixed placeholder; Reveal is the only way
// to read it, so a key reaches a response or a log only where code asks for it by name.
type Secret struct{ v string }

// Reveal returns the key, for the one screen or response that shows it to its holder.
func (s Secret) Reveal() string { return s.v }

// String returns the placeholder.
func (s Secret) String() string { return redacted }

// GoString returns the placeholder.
func (s Secret) GoString() string { return redacted }

// Format writes the placeholder for every verb.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// MarshalJSON writes the placeholder.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText writes the placeholder.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// LogValue logs the placeholder.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }
