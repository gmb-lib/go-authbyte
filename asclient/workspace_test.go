package asclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-quicktest/qt"
)

// A sign-in that names an organisation sends it as one tenant parameter and
// changes nothing else in the address.
func TestAnAuthorizationRequestCanNameATenant(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback", WithIssuer(testIssuer))

	base := AuthorizationRequest{CodeChallenge: "chal-1", State: "state-1", Nonce: "n-1", ACRValues: "eidScan"}
	named := base
	named.Tenant = "org-2"

	plain, err := url.Parse(c.AuthorizationURL(base))
	qt.Assert(t, qt.IsNil(err))
	with, err := url.Parse(c.AuthorizationURL(named))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.DeepEquals(with.Query()["tenant"], []string{"org-2"}))
	qt.Check(t, qt.IsFalse(plain.Query().Has("tenant")))

	rest := with.Query()
	rest.Del("tenant")
	qt.Check(t, qt.DeepEquals(rest, plain.Query()))
}

func TestAuthorizeURLForTenantAddsOnlyTheTenant(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	plain, err := url.Parse(c.AuthorizeURL("chal-1", "state-1", "eidScan"))
	qt.Assert(t, qt.IsNil(err))
	with, err := url.Parse(c.AuthorizeURLForTenant("chal-1", "state-1", "eidScan", "org-2"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.DeepEquals(with.Query()["tenant"], []string{"org-2"}))
	rest := with.Query()
	rest.Del("tenant")
	qt.Check(t, qt.DeepEquals(rest, plain.Query()))

	qt.Check(t, qt.Equals(c.AuthorizeURLForTenant("chal-1", "state-1", "eidScan", ""),
		c.AuthorizeURL("chal-1", "state-1", "eidScan")))
}

func TestWithNoTenantTheAddressesAreTheOnesBuiltBefore(t *testing.T) {
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	qt.Check(t, qt.Equals(c.AuthorizeURL("chal-1", "state-1", ""),
		"https://public/authorize?client_id=client-1&code_challenge=chal-1&code_challenge_method=S256"+
			"&redirect_uri=https%3A%2F%2Fapp%2Fcallback&response_type=code&state=state-1"))
	qt.Check(t, qt.Equals(c.AuthorizeURLForTenant("chal-1", "state-1", "eidScan", ""),
		"https://public/authorize?acr_values=eidScan&client_id=client-1&code_challenge=chal-1&code_challenge_method=S256"+
			"&redirect_uri=https%3A%2F%2Fapp%2Fcallback&response_type=code&state=state-1"))
	qt.Check(t, qt.Equals(c.AuthorizationURL(AuthorizationRequest{CodeChallenge: "chal-1", State: "state-1", Nonce: "n-1"}),
		"https://public/authorize?client_id=client-1&code_challenge=chal-1&code_challenge_method=S256&nonce=n-1"+
			"&redirect_uri=https%3A%2F%2Fapp%2Fcallback&response_type=code&scope=openid&state=state-1"))
}

func TestATenantValueCannotAddOrChangeAnotherParameter(t *testing.T) {
	const hostile = "a&tenant=b c/ž"
	c := New("https://public", "https://internal", "client-1", "https://app/callback")

	plain, err := url.Parse(c.AuthorizeURL("chal-1", "state-1", "eidScan"))
	qt.Assert(t, qt.IsNil(err))

	for name, raw := range map[string]string{
		"AuthorizeURLForTenant": c.AuthorizeURLForTenant("chal-1", "state-1", "eidScan", hostile),
		"AuthorizationURL": c.AuthorizationURL(AuthorizationRequest{
			CodeChallenge: "chal-1", State: "state-1", Nonce: "n-1", ACRValues: "eidScan", Tenant: hostile}),
	} {
		t.Run(name, func(t *testing.T) {
			u, err := url.Parse(raw)
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.DeepEquals(u.Query()["tenant"], []string{hostile}))
			qt.Check(t, qt.IsFalse(strings.Contains(raw, "&tenant=b")))

			rest := u.Query()
			rest.Del("tenant")
			for k, v := range plain.Query() {
				qt.Check(t, qt.DeepEquals(rest[k], v))
			}
		})
	}
}

// memberAuthority answers the token endpoint with the raw JSON it is given, and
// signs an ID token for a sign-in.
func memberAuthority(t *testing.T, extra string) (*idTokenAuthority, *httptest.Server) {
	t.Helper()

	a, _ := newIDTokenAuthority(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{{KeyID: a.kid, Key: &a.key.PublicKey, Algorithm: "ES256", Use: "sig"}},
			})
		case "/token":
			id := a.sign(t, goodIDClaims(time.Now()))
			_, _ = fmt.Fprintf(w, `{"access_token":"a","token_type":"DPoP","expires_in":300,"refresh_token":"r","id_token":%q%s}`, id, extra)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	return a, srv
}

func TestTheTokenAnswersListOfOrganisationsIsReturnedAsSent(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		want  []Membership
	}{
		{"two", `,"memberships":[{"tenant":"t-2","name":"Second"},{"tenant":"t-1","name":"First"}]`,
			[]Membership{{Tenant: "t-2", Name: "Second"}, {Tenant: "t-1", Name: "First"}}},
		{"no key", ``, nil},
		{"empty list", `,"memberships":[]`, nil},
		{"an entry without a name", `,"memberships":[{"tenant":"t-1"}]`, []Membership{{Tenant: "t-1", Name: ""}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, srv := memberAuthority(t, tt.extra)
			c := New("https://public", srv.URL, "client-1", "https://app/callback", WithIssuer(testIssuer))
			key, err := GenerateKey()
			qt.Assert(t, qt.IsNil(err))

			got, err := c.ExchangeCode(context.Background(), key, "code-1", "verifier-1")
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.HasLen(got.Memberships, len(tt.want)))
			if len(tt.want) > 0 {
				qt.Check(t, qt.DeepEquals(got.Memberships, tt.want))
			}

			got, err = c.Refresh(context.Background(), key, "r")
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.HasLen(got.Memberships, len(tt.want)))
			if len(tt.want) > 0 {
				qt.Check(t, qt.DeepEquals(got.Memberships, tt.want))
			}
		})
	}

	t.Run("through ExchangeSignIn", func(t *testing.T) {
		_, srv := memberAuthority(t, `,"memberships":[{"tenant":"t-1","name":"First"},{"tenant":"t-2"}]`)
		c := New("https://public", srv.URL, "client-1", "https://app/callback", WithIssuer(testIssuer))
		key, err := GenerateKey()
		qt.Assert(t, qt.IsNil(err))

		got, _, err := c.ExchangeSignIn(context.Background(), key, "code-1", "verifier-1", IDTokenCheck{Nonce: "n-1"})
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.DeepEquals(got.Memberships, []Membership{{Tenant: "t-1", Name: "First"}, {Tenant: "t-2", Name: ""}}))
	})
}

func TestAMembershipWithNoNameIsWrittenWithAnEmptyName(t *testing.T) {
	b, err := json.Marshal(Membership{Tenant: "t-1"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(b), `{"tenant":"t-1","name":""}`))
}

func TestCheckWorkspace(t *testing.T) {
	tests := []struct {
		name        string
		asked, held string
		refused     bool
	}{
		{"equal", "w-1", "w-1", false},
		{"different", "w-2", "w-1", true},
		{"asked empty, held set", "", "w-1", false},
		{"both empty", "", "", false},
		{"asked set, held empty", "w-1", "", true},
		{"differing only in case", "W-1", "w-1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckWorkspace(tt.asked, tt.held)
			if !tt.refused {
				qt.Check(t, qt.IsNil(err))

				return
			}
			var p *WorkspaceRefusal
			qt.Assert(t, qt.ErrorAs(err, &p))
			qt.Check(t, qt.Equals(p.Status, 409))
			qt.Check(t, qt.Equals(p.StatusCode(), 409))
			qt.Check(t, qt.Equals(p.Code, OtherWorkspaceCode))
			qt.Check(t, qt.Equals(p.Detail, "this page was opened for another workspace"))
			qt.Check(t, qt.Equals(p.Error(), "err:session:otherWorkspace: this page was opened for another workspace"))
			qt.Check(t, qt.IsFalse(strings.Contains(p.Error(), tt.asked)))
			qt.Check(t, qt.IsFalse(tt.held != "" && strings.Contains(p.Error(), tt.held)))
		})
	}
}

func TestTheWorkspaceConstantsAreTheAgreedStrings(t *testing.T) {
	qt.Check(t, qt.Equals(WorkspaceHeader, "Workspace-Id"))
	qt.Check(t, qt.Equals(OtherWorkspaceCode, "err:session:otherWorkspace"))
	qt.Check(t, qt.Equals(NotMemberCode, "err:membership:notMember"))

	var p *WorkspaceRefusal
	qt.Assert(t, qt.ErrorAs(CheckWorkspace("a", "b"), &p))
	qt.Check(t, qt.Equals(p.Code, "err:session:otherWorkspace"))
}

func TestNotMember(t *testing.T) {
	const body = `{"type":"about:blank","title":"Forbidden","status":403,"code":"err:membership:notMember"}`
	other := `{"title":"Forbidden","status":403,"code":"err:membership:other"}`

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"403 with the code", &Error{Status: 403, Body: body}, true},
		{"wrapped", fmt.Errorf("sign-in: %w", &Error{Status: 403, Body: body}), true},
		{"403 with another code", &Error{Status: 403, Body: other}, false},
		{"401 with the code", &Error{Status: 401, Body: strings.Replace(body, "403", "401", 1)}, false},
		{"a body that is not JSON", &Error{Status: 403, Body: "forbidden"}, false},
		{"a JSON array", &Error{Status: 403, Body: `["err:membership:notMember"]`}, false},
		{"a JSON string", &Error{Status: 403, Body: `"err:membership:notMember"`}, false},
		{"nil", nil, false},
		{"another type", fmt.Errorf("plain"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qt.Check(t, qt.Equals(NotMember(tt.err), tt.want))
		})
	}
}
