package authclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// subjectToken builds a token-shaped string carrying the given claims. The
// client never verifies a subject token itself — the authority does, when it
// is asked to exchange it — so the signature here is a placeholder.
func subjectToken(t *testing.T, cl map[string]any) string {
	t.Helper()

	enc := func(v any) string {
		b, err := json.Marshal(v)
		qt.Assert(t, qt.IsNil(err))

		return base64.RawURLEncoding.EncodeToString(b)
	}

	return enc(map[string]any{"alg": "ES256", "typ": "at+jwt"}) + "." + enc(cl) + ".c2lnbmF0dXJl"
}

// personToken is one person's token as an edge holds it: the same subject
// every time, with whatever organisation and sign-in it was minted for.
func personToken(t *testing.T, tenant, loginMethod string, exp time.Time) string {
	t.Helper()

	return subjectToken(t, map[string]any{
		"iss":          "http://auth.local",
		"sub":          "internal-123",
		"tenant":       tenant,
		"login_method": loginMethod,
		"exp":          exp.Unix(),
	})
}

// waitPast sleeps until the given whole-second expiry has passed.
func waitPast(exp time.Time) {
	time.Sleep(time.Until(time.Unix(exp.Unix(), 0)) + 50*time.Millisecond)
}

// One person in two organisations holds two tokens, each minted for one of
// them. A token exchanged for the first must never be handed out for the
// second: the callee would act in the first organisation for a person who is
// now working in the second.
func TestASecondOrganisationsTokenIsExchangedNotServedFromTheFirst(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	first := personToken(t, "T1", "webEid", exp)
	second := personToken(t, "T2", "webEid", exp)

	tok1, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", first)
	qt.Assert(t, qt.IsNil(err))
	tok2, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", second)
	qt.Assert(t, qt.IsNil(err))

	calls := stub.calls()
	qt.Assert(t, qt.HasLen(calls, 2))
	qt.Check(t, qt.Equals(calls[0]["subject_token"], first))
	qt.Check(t, qt.Equals(calls[1]["subject_token"], second))
	qt.Check(t, qt.Not(qt.Equals(tok2, tok1)))
}

// The same holds for anything else the token carries. A token exchanged after
// a weaker sign-in must not be handed out after a stronger one: the callee
// reads the sign-in method from the token it receives.
func TestAStrongerSignInIsExchangedNotServedFromTheWeaker(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)

	weaker := personToken(t, "T1", "smartIdBasic", exp)
	stronger := personToken(t, "T1", "webEid", exp)

	_, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", weaker)
	qt.Assert(t, qt.IsNil(err))
	_, err = c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", stronger)
	qt.Assert(t, qt.IsNil(err))

	calls := stub.calls()
	qt.Assert(t, qt.HasLen(calls, 2))
	qt.Check(t, qt.Equals(calls[1]["subject_token"], stronger))
}

// The cache still does its job: the same subject token, asked again for the
// same audience and scope, is served without a second exchange.
func TestTheSameSubjectTokenIsServedFromTheCache(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	tok := personToken(t, "T1", "webEid", time.Now().Add(time.Hour))

	first, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", tok)
	qt.Assert(t, qt.IsNil(err))
	again, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", tok)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.HasLen(stub.calls(), 1))
	qt.Check(t, qt.Equals(again, first))
}

// The authority may mint an exchanged token that outlives the token it was
// exchanged for. Once the subject token has expired it no longer speaks for
// anyone, so a token exchanged for it is not handed out again: the next call
// asks the authority, which then decides.
func TestNoCachedTokenIsServedPastTheSubjectTokensExpiry(t *testing.T) {
	stub := newRecordingTokenStub(t) // answers expires_in 300
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	exp := time.Now().Add(1500 * time.Millisecond)
	tok := personToken(t, "T1", "webEid", exp)

	_, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", tok)
	qt.Assert(t, qt.IsNil(err))
	_, err = c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(stub.calls(), 1)) // reused while the subject token lives

	waitPast(exp)

	_, err = c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", tok)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(stub.calls(), 2))
}

// A subject token already past its expiry when it is presented leaves nothing
// in the cache to be served later.
func TestAnExpiredSubjectTokenIsNeverServedFromTheCache(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	tok := personToken(t, "T1", "webEid", time.Now().Add(-time.Minute))

	for range 2 {
		_, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", tok)
		qt.Assert(t, qt.IsNil(err))
	}

	qt.Check(t, qt.HasLen(stub.calls(), 2))
}

// When the subject token's expiry cannot be read, how long its exchanged token
// may be reused cannot be bounded, so it is not cached at all.
func TestASubjectTokenWithNoReadableExpiryIsNotCached(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	for _, tok := range []string{
		"not-a-token",
		subjectToken(t, map[string]any{"sub": "internal-123", "tenant": "T1"}), // no exp
	} {
		for range 2 {
			_, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "internal-123", tok)
			qt.Assert(t, qt.IsNil(err))
		}
	}

	qt.Check(t, qt.HasLen(stub.calls(), 4))
}

// Every renewed subject token is a new key, so a cache that only ever added
// entries would grow for as long as the process runs. An entry that can no
// longer be served is removed when the next one is stored.
func TestEntriesThatCanNoLongerBeServedAreRemoved(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	exp := time.Now().Add(1500 * time.Millisecond)
	for _, person := range []string{"person-1", "person-2", "person-3"} {
		tok := subjectToken(t, map[string]any{"sub": person, "tenant": "T1", "exp": exp.Unix()})
		_, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", person, tok)
		qt.Assert(t, qt.IsNil(err))
	}

	waitPast(exp)

	live := subjectToken(t, map[string]any{"sub": "person-4", "tenant": "T1", "exp": time.Now().Add(time.Hour).Unix()})
	_, err := c.AcquireDelegatedToken(ctx, "svc:engine", "projects:read", "person-4", live)
	qt.Assert(t, qt.IsNil(err))

	c.mu.Lock()
	defer c.mu.Unlock()

	var delegated []string
	for k := range c.tokens {
		if strings.HasPrefix(k, "obo|") {
			delegated = append(delegated, k)
		}
	}
	qt.Check(t, qt.HasLen(delegated, 1))
}

// The key holds a fingerprint of the subject token, never the token itself: a
// person's credential is not kept anywhere it was not needed.
func TestTheCacheKeyDoesNotHoldTheSubjectToken(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)

	tok := personToken(t, "T1", "webEid", time.Now().Add(time.Hour))
	_, err := c.AcquireDelegatedToken(context.Background(), "svc:engine", "projects:read", "internal-123", tok)
	qt.Assert(t, qt.IsNil(err))

	c.mu.Lock()
	defer c.mu.Unlock()

	for k := range c.tokens {
		qt.Check(t, qt.IsFalse(strings.Contains(k, tok)))
		qt.Check(t, qt.IsFalse(strings.Contains(k, strings.Split(tok, ".")[1])))
	}
}
