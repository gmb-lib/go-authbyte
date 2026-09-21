package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// recordingTokenStub serves /token, records the form of every request it was asked, and
// answers each one with a distinct token so a caller cannot pass by reusing one.
type recordingTokenStub struct {
	mu     sync.Mutex
	forms  []map[string]string
	server *httptest.Server
}

func newRecordingTokenStub(t *testing.T) *recordingTokenStub {
	t.Helper()
	s := &recordingTokenStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/token") {
			w.WriteHeader(http.StatusNotFound)

			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		s.mu.Lock()
		got := map[string]string{}
		for k := range r.PostForm {
			got[k] = r.PostForm.Get(k)
		}
		s.forms = append(s.forms, got)
		n := len(s.forms)
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-" + got["tenant"] + "-" + strconv.Itoa(n),
			"expires_in":   300,
		})
	}))
	t.Cleanup(s.server.Close)

	return s
}

func (s *recordingTokenStub) calls() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]string, len(s.forms))
	copy(out, s.forms)

	return out
}

// Naming an organisation puts it on the token request; not naming one leaves the
// field off entirely. An empty value would be a request to act for an
// organisation called "", which is not the same as not naming one.
func TestTheOrganisationIsSentOnlyWhenThereIsOne(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	if _, err := c.AcquireServiceToken(ctx, "svc:document", "documents:read"); err != nil {
		t.Fatalf("plain service token: %v", err)
	}
	if _, err := c.AcquireServiceTokenForTenant(ctx, "svc:document", "documents:read", "org-a"); err != nil {
		t.Fatalf("tenanted service token: %v", err)
	}

	calls := stub.calls()
	if len(calls) != 2 {
		t.Fatalf("expected two token requests, got %d", len(calls))
	}
	if _, present := calls[0]["tenant"]; present {
		t.Fatalf("a plain service token must not name an organisation: %v", calls[0])
	}
	if calls[1]["tenant"] != "org-a" {
		t.Fatalf("the organisation must travel on the token request: %v", calls[1])
	}
	// Everything else is unchanged, so no existing caller moves.
	if calls[0]["grant_type"] != "client_credentials" || calls[0]["audience"] != "svc:document" {
		t.Fatalf("the grant is unchanged: %v", calls[0])
	}
}

// THE ONE THAT MATTERS. A service acting for many organisations must never be
// handed a token minted for a different one: the callee would honour it, and the
// boundary those organisations are relying on would be gone. The cache key is
// what prevents it, so this asserts the mint happens again and the tokens differ.
func TestATokenIsNeverReusedAcrossOrganisations(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	a, err := c.AcquireServiceTokenForTenant(ctx, "svc:document", "documents:write", "org-a")
	if err != nil {
		t.Fatalf("org-a: %v", err)
	}
	b, err := c.AcquireServiceTokenForTenant(ctx, "svc:document", "documents:write", "org-b")
	if err != nil {
		t.Fatalf("org-b: %v", err)
	}

	if a == b {
		t.Fatalf("two organisations were served the same token (%q)", a)
	}
	if got := len(stub.calls()); got != 2 {
		t.Fatalf("each organisation mints its own token: expected 2 requests, got %d", got)
	}

	// And a plain service token is a third thing again — an untenanted call must
	// not be served a token that carries an organisation.
	plain, err := c.AcquireServiceToken(ctx, "svc:document", "documents:write")
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	if plain == a || plain == b {
		t.Fatalf("an untenanted call was served an organisation's token (%q)", plain)
	}
}

// Within one organisation the cache still does its job — this is not a change
// that quietly mints a token per call.
func TestTheSameOrganisationReusesItsToken(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	first, err := c.AcquireServiceTokenForTenant(ctx, "svc:document", "documents:write", "org-a")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := c.AcquireServiceTokenForTenant(ctx, "svc:document", "documents:write", "org-a")
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first != second {
		t.Fatalf("the same organisation must reuse its cached token")
	}
	if got := len(stub.calls()); got != 1 {
		t.Fatalf("the cache must serve the second call: expected 1 request, got %d", got)
	}
}

// The existing entry point is unchanged for everyone who already calls it.
func TestTheUntenantedEntryPointIsUnchanged(t *testing.T) {
	stub := newRecordingTokenStub(t)
	c := newTestClient(t, stub.server.URL)
	ctx := context.Background()

	first, err := c.AcquireServiceToken(ctx, "svc:document", "documents:read")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := c.AcquireServiceTokenForTenant(ctx, "svc:document", "documents:read", "")
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	// An empty organisation IS the untenanted call, and shares its cache entry.
	if first != second {
		t.Fatalf("an empty organisation must be the same call as no organisation")
	}
	if got := len(stub.calls()); got != 1 {
		t.Fatalf("expected 1 request, got %d", got)
	}
}
