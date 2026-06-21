// Package authclient is the in-process auth-client library. It validates
// inbound tokens + DPoP proofs (Azugo middleware) and acquires/attaches
// DPoP-bound service tokens on outbound service-to-service calls — all on the
// hot path with no per-request call home (JWKS and service tokens are cached).
package authclient

import (
	"time"

	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Replay backend identifiers.
const (
	ReplayBackendMemory = "memory"
	ReplayBackendRedis  = "redis"
)

// Configuration is the auth-client library configuration. It is
// bound as a sub-configuration of each consuming service's Azugo Configuration.
// Only IssuerURL, ServiceAudience and the client id/secret are typically set
// per service; everything else has safe defaults.
type Configuration struct {
	// IssuerURL is where discovery + JWKS are fetched and the expected `iss`.
	IssuerURL string `mapstructure:"issuer_url" validate:"required,url"`
	// JWKSURL overrides the JWKS location (else derived from IssuerURL).
	JWKSURL string `mapstructure:"jwks_url" validate:"omitempty,url"`
	// JWKSCacheTTL is the public-key cache lifetime.
	JWKSCacheTTL time.Duration `mapstructure:"jwks_cache_ttl" validate:"required,gt=0"`

	// ServiceAudience is this service's own `aud` — inbound tokens must target
	// it.
	ServiceAudience string `mapstructure:"service_audience" validate:"required"`
	// ServiceClientID / ServiceClientSecret authenticate outbound
	// client-credentials requests. Optional for services that never call out.
	ServiceClientID     string `mapstructure:"service_client_id"`
	ServiceClientSecret string `mapstructure:"service_client_secret"`
	// ServiceTokenEarlyRefresh refreshes the own token this long before exp.
	ServiceTokenEarlyRefresh time.Duration `mapstructure:"service_token_early_refresh" validate:"required,gt=0"`

	// DPoPProofMaxAge is the maximum accepted age for inbound proofs.
	DPoPProofMaxAge time.Duration `mapstructure:"dpop_proof_max_age" validate:"required,gt=0"`
	// TokenClockSkewLeeway is the leeway on exp/iat/proof age.
	TokenClockSkewLeeway time.Duration `mapstructure:"token_clock_skew_leeway" validate:"gte=0"`

	// DPoPReplayBackend selects the jti replay store (memory | redis).
	DPoPReplayBackend string `mapstructure:"dpop_replay_backend" validate:"oneof=memory redis"`
	// RedisURL is required when DPoPReplayBackend is redis.
	RedisURL string `mapstructure:"redis_url" validate:"required_if=DPoPReplayBackend redis"`

	// DPoPNonceEnabled requires + issues a server DPoP-Nonce on inbound.
	DPoPNonceEnabled bool `mapstructure:"dpop_nonce_enabled"`
	// DPoPNonceTTL is the lifetime of an issued nonce.
	DPoPNonceTTL time.Duration `mapstructure:"dpop_nonce_ttl" validate:"required,gt=0"`
	// RequireDPoP enforces DPoP on inbound (true everywhere internally).
	RequireDPoP bool `mapstructure:"require_dpop"`
}

// Bind registers defaults and environment-variable bindings under prefix.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".jwks_cache_ttl", 10*time.Minute)
	v.SetDefault(prefix+".service_token_early_refresh", 30*time.Second)
	v.SetDefault(prefix+".dpop_proof_max_age", 60*time.Second)
	v.SetDefault(prefix+".token_clock_skew_leeway", 30*time.Second)
	v.SetDefault(prefix+".dpop_replay_backend", ReplayBackendMemory)
	v.SetDefault(prefix+".dpop_nonce_enabled", true)
	v.SetDefault(prefix+".dpop_nonce_ttl", 5*time.Minute)
	v.SetDefault(prefix+".require_dpop", true)

	// Secrets are loaded from the remote secret store (Vault), never env files.
	if secret, err := corecfg.LoadRemoteSecret("SERVICE_CLIENT_SECRET"); err == nil && secret != "" {
		v.SetDefault(prefix+".service_client_secret", secret)
	}

	_ = v.BindEnv(prefix+".issuer_url", "AUTH_ISSUER_URL")
	_ = v.BindEnv(prefix+".jwks_url", "AUTH_JWKS_URL")
	_ = v.BindEnv(prefix+".jwks_cache_ttl", "AUTH_JWKS_CACHE_TTL")
	_ = v.BindEnv(prefix+".service_audience", "SERVICE_AUDIENCE")
	_ = v.BindEnv(prefix+".service_client_id", "SERVICE_CLIENT_ID")
	_ = v.BindEnv(prefix+".service_client_secret", "SERVICE_CLIENT_SECRET")
	_ = v.BindEnv(prefix+".service_token_early_refresh", "SERVICE_TOKEN_EARLY_REFRESH")
	_ = v.BindEnv(prefix+".dpop_proof_max_age", "DPOP_PROOF_MAX_AGE")
	_ = v.BindEnv(prefix+".token_clock_skew_leeway", "TOKEN_CLOCK_SKEW_LEEWAY")
	_ = v.BindEnv(prefix+".dpop_replay_backend", "DPOP_REPLAY_BACKEND")
	_ = v.BindEnv(prefix+".redis_url", "REDIS_URL")
	_ = v.BindEnv(prefix+".dpop_nonce_enabled", "DPOP_NONCE_ENABLED")
	_ = v.BindEnv(prefix+".dpop_nonce_ttl", "DPOP_NONCE_TTL")
	_ = v.BindEnv(prefix+".require_dpop", "REQUIRE_DPOP")
}

// Validate validates the configuration.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
