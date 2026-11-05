package asclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/dpop"
)

// seenCall is what the Auth Service received for one connections call.
type seenCall struct {
	method, path, authorization string
	proof                       *dpop.Result
	proofErr                    error
}

// connectionsServer answers every call with status and body, and records what it
// received, the proof checked against the request it came with.
func connectionsServer(t *testing.T, status int, body string) (*httptest.Server, chan seenCall) {
	t.Helper()
	seen := make(chan seenCall, 4)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := seenCall{method: r.Method, path: r.URL.EscapedPath(), authorization: r.Header.Get("Authorization")}
		got.proof, got.proofErr = dpop.Verify(r.Header.Get("DPoP"), dpop.VerifyOptions{
			Method: r.Method, URL: srv.URL + r.URL.EscapedPath(), AccessToken: "person-token", MaxAge: time.Minute,
		})
		seen <- got
		if body != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv, seen
}

// checkProven checks a call went out as the person's own token, bound to the
// session's key by a proof of this very request.
func checkProven(t *testing.T, got seenCall, method, path, thumbprint string) {
	t.Helper()
	qt.Check(t, qt.Equals(got.method, method))
	qt.Check(t, qt.Equals(got.path, path))
	qt.Check(t, qt.Equals(got.authorization, "DPoP person-token"))
	qt.Assert(t, qt.IsNil(got.proofErr))
	qt.Check(t, qt.Equals(got.proof.Thumbprint, thumbprint))
}

// A person's own connected apps are read with their own token, proven by the
// session's key: each of their assistants in the workspace, each app with its
// public name, the app's name and when it connected and was last used, never
// used read as nil.
func TestAPersonsOwnConnectionsAreReadWithTheirOwnToken(t *testing.T) {
	srv, seen := connectionsServer(t, http.StatusOK, `{"assistants":[
		{"key":"svc:assistant-01J0000000000000000000000A","name":"Assistant 1","connections":[
			{"id":"c-2","app":"Claude Code","connectedAt":"2026-11-05T08:10:00Z","lastUsed":null},
			{"id":"c-1","app":"Claude Code","connectedAt":"2026-10-30T09:20:00Z","lastUsed":"2026-11-05T09:30:00Z"}]},
		{"key":"svc:assistant-01J0000000000000000000000B","name":"Assistant 4","connections":[]}]}`)
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	tp, err := dpop.Thumbprint(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))
	c := New("https://public", srv.URL, "client-1", "https://app/callback")

	own, err := c.OwnConnections(context.Background(), key, "person-token")
	qt.Assert(t, qt.IsNil(err))
	checkProven(t, <-seen, http.MethodGet, "/identity/connections", tp)

	used := time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC)
	qt.Check(t, qt.DeepEquals(own, []OwnAssistant{
		{Key: "svc:assistant-01J0000000000000000000000A", Name: "Assistant 1", Connections: []Connection{
			{ID: "c-2", App: "Claude Code", ConnectedAt: time.Date(2026, 11, 5, 8, 10, 0, 0, time.UTC)},
			{ID: "c-1", App: "Claude Code", ConnectedAt: time.Date(2026, 10, 30, 9, 20, 0, 0, time.UTC), LastUsed: &used},
		}},
		{Key: "svc:assistant-01J0000000000000000000000B", Name: "Assistant 4", Connections: []Connection{}},
	}))
}

// One of the person's own apps is signed out by its public name, in the path.
func TestAPersonSignsOneOfTheirAppsOutByItsName(t *testing.T) {
	srv, seen := connectionsServer(t, http.StatusNoContent, "")
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	tp, err := dpop.Thumbprint(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))
	c := New("https://public", srv.URL, "client-1", "https://app/callback")

	qt.Assert(t, qt.IsNil(c.SignOutOwnConnection(context.Background(), key, "person-token", "c-1")))
	checkProven(t, <-seen, http.MethodDelete, "/identity/connections/c-1", tp)
}

// An administrator reads one assistant's connected apps, signs one out, and ends
// them all, each with their own token: the assistant's key and the app's name in
// the path.
func TestAnAdministratorReadsSignsOutAndEndsAnAssistantsApps(t *testing.T) {
	const assistant = "svc:assistant-01J0000000000000000000000A"
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	tp, err := dpop.Thumbprint(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))

	srv, seen := connectionsServer(t, http.StatusOK, `{"connections":[
		{"id":"c-1","app":"Claude Code","connectedAt":"2026-10-30T09:20:00Z","lastUsed":null}]}`)
	c := New("https://public", srv.URL, "client-1", "https://app/callback")
	lines, err := c.AssistantConnections(context.Background(), key, "person-token", assistant)
	qt.Assert(t, qt.IsNil(err))
	checkProven(t, <-seen, http.MethodGet, "/identity/assistants/"+assistant+"/connections", tp)
	qt.Check(t, qt.DeepEquals(lines, []Connection{
		{ID: "c-1", App: "Claude Code", ConnectedAt: time.Date(2026, 10, 30, 9, 20, 0, 0, time.UTC)},
	}))

	srv, seen = connectionsServer(t, http.StatusNoContent, "")
	c = New("https://public", srv.URL, "client-1", "https://app/callback")
	qt.Assert(t, qt.IsNil(c.SignOutAssistantConnection(context.Background(), key, "person-token", assistant, "c-1")))
	checkProven(t, <-seen, http.MethodDelete, "/identity/assistants/"+assistant+"/connections/c-1", tp)

	qt.Assert(t, qt.IsNil(c.EndAssistantConnections(context.Background(), key, "person-token", assistant)))
	checkProven(t, <-seen, http.MethodDelete, "/identity/assistants/"+assistant+"/connections", tp)
}

// A refusal is an *Error carrying the status and the Auth Service's own body,
// so an edge relays the problem as it came; a sign-out answered 200 rather than
// 204 is not taken as done.
func TestAConnectionsRefusalIsAnErrorWithItsBody(t *testing.T) {
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	const problem = `{"type":"about:blank","status":404,"code":"err:connection:not_found"}`

	for name, call := range map[string]func(c *Client) error{
		"own list": func(c *Client) error {
			_, err := c.OwnConnections(context.Background(), key, "person-token")
			return err
		},
		"own sign-out": func(c *Client) error {
			return c.SignOutOwnConnection(context.Background(), key, "person-token", "c-9")
		},
		"assistant's list": func(c *Client) error {
			_, err := c.AssistantConnections(context.Background(), key, "person-token", "svc:assistant-01J0000000000000000000000A")
			return err
		},
		"assistant's sign-out": func(c *Client) error {
			return c.SignOutAssistantConnection(context.Background(), key, "person-token", "svc:assistant-01J0000000000000000000000A", "c-9")
		},
		"assistant's end": func(c *Client) error {
			return c.EndAssistantConnections(context.Background(), key, "person-token", "svc:assistant-01J0000000000000000000000A")
		},
	} {
		srv, seen := connectionsServer(t, http.StatusNotFound, problem)
		err := call(New("https://public", srv.URL, "client-1", "https://app/callback"))
		<-seen
		var asErr *Error
		qt.Assert(t, qt.ErrorAs(err, &asErr), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(asErr.Status, http.StatusNotFound), qt.Commentf("%s", name))
		qt.Check(t, qt.Equals(asErr.Body, problem), qt.Commentf("%s", name))
	}

	srv, seen := connectionsServer(t, http.StatusOK, `{}`)
	err = New("https://public", srv.URL, "client-1", "https://app/callback").
		SignOutOwnConnection(context.Background(), key, "person-token", "c-1")
	<-seen
	var asErr *Error
	qt.Assert(t, qt.ErrorAs(err, &asErr))
	qt.Check(t, qt.Equals(asErr.Status, http.StatusOK))
}

// A name or a key that is empty, or that would leave its path segment, is
// refused before anything is sent, so a call meant for one connection can
// never reach another route; an empty token likewise.
func TestAConnectionsCallThatNamesNothingIsNotSent(t *testing.T) {
	srv, seen := connectionsServer(t, http.StatusNoContent, "")
	c := New("https://public", srv.URL, "client-1", "https://app/callback")
	key, err := GenerateKey()
	qt.Assert(t, qt.IsNil(err))
	ctx := context.Background()
	const assistant = "svc:assistant-01J0000000000000000000000A"

	for name, err := range map[string]error{
		"no name":             c.SignOutOwnConnection(ctx, key, "person-token", ""),
		"a name with /":       c.SignOutOwnConnection(ctx, key, "person-token", "c-1/../../x"),
		"a dot name":          c.SignOutOwnConnection(ctx, key, "person-token", ".."),
		"no assistant":        c.EndAssistantConnections(ctx, key, "person-token", ""),
		"an assistant with /": c.EndAssistantConnections(ctx, key, "person-token", "svc:x/connections/c-1"),
		"no app named":        c.SignOutAssistantConnection(ctx, key, "person-token", assistant, ""),
		"no token":            c.SignOutOwnConnection(ctx, key, "", "c-1"),
		"no token to read": func() error {
			_, err := c.OwnConnections(ctx, key, " ")
			return err
		}(),
		"no assistant to read": func() error {
			_, err := c.AssistantConnections(ctx, key, "person-token", "")
			return err
		}(),
	} {
		qt.Check(t, qt.Not(qt.IsNil(err)), qt.Commentf("%s", name))
	}
	select {
	case got := <-seen:
		t.Fatalf("a call naming nothing was sent: %+v", got)
	default:
	}
}
