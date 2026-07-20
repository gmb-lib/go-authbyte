package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient builds a Client against a stub auth service that issues a
// static bearer for any client-credentials request.
func newTestClient(t *testing.T, issuerURL string) *Client {
	t.Helper()

	c, err := New(&Configuration{
		IssuerURL:                issuerURL,
		ServiceAudience:          "svc:test",
		ServiceClientID:          "svc:caller",
		ServiceClientSecret:      "secret",
		JWKSCacheTTL:             time.Minute,
		ServiceTokenEarlyRefresh: time.Second,
		DPoPProofMaxAge:          time.Minute,
		DPoPReplayBackend:        ReplayBackendMemory,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return c
}

// slowStub serves the /token endpoint immediately and delays every other
// request by delay before answering 200.
func slowStub(delay time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 300})

			return
		}

		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

func TestDoServiceWithTimeoutExpires(t *testing.T) {
	srv := httptest.NewServer(slowStub(400 * time.Millisecond))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	_, err := c.DoServiceWithTimeout(context.Background(), 50*time.Millisecond,
		"svc:target", "things:read", http.MethodPost, srv.URL+"/slow", nil, []byte(`{}`))
	if err == nil {
		t.Fatal("expected a deadline error, got success")
	}
}

func TestDoServiceWithTimeoutOutlastsSlowUpstream(t *testing.T) {
	srv := httptest.NewServer(slowStub(400 * time.Millisecond))
	defer srv.Close()

	c := newTestClient(t, srv.URL)

	resp, err := c.DoServiceWithTimeout(context.Background(), 5*time.Second,
		"svc:target", "things:read", http.MethodPost, srv.URL+"/slow", nil, []byte(`{}`))
	if err != nil {
		t.Fatalf("DoServiceWithTimeout: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Fatalf("body = %s", resp.Body)
	}
}
