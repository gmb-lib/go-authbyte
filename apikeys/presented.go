package apikeys

// TokenType names a key as the subject token of a token exchange [RFC 8693 §2.1]: a service that
// received a key hands it to the authority with this type, and the authority checks it as a key. An
// absolute URI of this library's own, as [RFC 8693 §3] allows for a type it does not define.
const TokenType = "urn:gmb:params:oauth:token-type:api-key"

// Presented reads a key a caller presented, by its shape alone: the scheme, the lengths and the
// alphabets. It derives nothing and looks nothing up, so it says only that the key could be one of this
// family's, never that it is one. A service that hands keys on to be checked elsewhere uses it to refuse
// what can never be a key before sending anything, and to hold the key as a Secret from there on. Every
// refusal is ErrInvalid and names nothing of the input.
func (s *Scheme) Presented(key string) (Secret, error) {
	if _, err := s.parse(key); err != nil {
		return Secret{}, err
	}

	return Secret{v: key}, nil
}
