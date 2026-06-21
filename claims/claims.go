// Package claims defines the JWT claim model shared by the Identity/Auth
// service (which issues tokens) and the auth-client library (which validates
// them). Keeping the model in one place guarantees the issuer and every
// consumer agree on the wire format.
package claims

import (
	"strings"

	"azugo.io/azugo/token"
	"github.com/golang-jwt/jwt/v5"
)

// Standard claim names used across the platform.
const (
	ClaimScope       = "scope"
	ClaimLoA         = "loa"
	ClaimLoginMethod = "login_method"
	ClaimName        = "name"
	ClaimGivenName   = "given_name"
	ClaimFamilyName  = "family_name"
	ClaimConfirm     = "cnf"
	ClaimClientID    = "client_id"
)

// ServiceSubjectPrefix marks a subject as a service (machine) identity rather
// than a human user. e.g. "svc:signing-orchestrator".
const ServiceSubjectPrefix = "svc:"

// Confirmation is the RFC 7800 `cnf` claim. For DPoP-bound tokens it carries
// the JWK SHA-256 thumbprint (`jkt`) of the key the token is sender-constrained
// to.
type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

// Claims is the union of every claim the platform issues. A single struct
// covers both user and service tokens; fields that do not apply to a given
// token type are simply omitted (`omitempty`). It embeds golang-jwt's
// RegisteredClaims so the standard temporal/identity validations apply.
type Claims struct {
	jwt.RegisteredClaims

	// Scope is space-delimited per OAuth2 convention (e.g.
	// "envelopes:write documents:read").
	Scope string `json:"scope,omitempty"`
	// LoA is the assurance level for user tokens (e.g. "substantial", "high").
	LoA string `json:"loa,omitempty"`
	// LoginMethod drives the signing-identity binding for user tokens.
	LoginMethod string `json:"login_method,omitempty"`

	// Display fields (user tokens only).
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`

	// ClientID is the requesting service client id (service tokens).
	ClientID string `json:"client_id,omitempty"`

	// Confirmation holds the DPoP key thumbprint binding.
	Confirmation *Confirmation `json:"cnf,omitempty"`
}

// IsService reports whether the token represents a service identity.
func (c *Claims) IsService() bool {
	return strings.HasPrefix(c.Subject, ServiceSubjectPrefix)
}

// Thumbprint returns the bound DPoP key thumbprint, or "" if the token is not
// DPoP-bound.
func (c *Claims) Thumbprint() string {
	if c.Confirmation == nil {
		return ""
	}

	return c.Confirmation.JKT
}

// Scopes splits the space-delimited scope string into individual scope tokens.
func (c *Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// ToUserClaims converts the validated claims into the claim map consumed by
// azugo's user.New. Scopes are pre-split into a slice so azugo treats each
// "group:level" entry as a distinct scope (its default item separator is a
// comma, which would not split our space-delimited form).
func (c *Claims) ToUserClaims() map[string]token.ClaimStrings {
	m := map[string]token.ClaimStrings{
		"sub": {c.Subject},
	}

	if scopes := c.Scopes(); len(scopes) > 0 {
		m[ClaimScope] = scopes
	}
	if c.LoA != "" {
		m[ClaimLoA] = token.ClaimStrings{c.LoA}
	}
	if c.LoginMethod != "" {
		m[ClaimLoginMethod] = token.ClaimStrings{c.LoginMethod}
	}
	if c.Name != "" {
		m[ClaimName] = token.ClaimStrings{c.Name}
	}
	if c.GivenName != "" {
		m[ClaimGivenName] = token.ClaimStrings{c.GivenName}
	}
	if c.FamilyName != "" {
		m[ClaimFamilyName] = token.ClaimStrings{c.FamilyName}
	}
	if c.ClientID != "" {
		m[ClaimClientID] = token.ClaimStrings{c.ClientID}
	}

	return m
}
