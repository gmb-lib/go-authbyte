package claims

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"azugo.io/azugo/user"
	"github.com/golang-jwt/jwt/v5"
)

// testIDCodeLV returns a Latvian personal identity code in the PNO form a token
// carries: the country, a six-digit leading group and a five-digit serial, built
// from one repeated digit so it reads as a placeholder at a glance.
//
// It is assembled from those parts at run time rather than written as a literal —
// an identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's code
// to a reader. Nothing here asserts the value; it is present only so the claim set
// has the shape a real token has.
func testIDCodeLV(digit int) string {
	d := strconv.Itoa(digit)

	return "PNOLV-" + strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5)
}

// The tenant claim must survive the full path: struct → wire JSON → struct →
// the azugo claim map a resource service reads it from. Multi-tenant services
// scope every operation by this value, so dropping it anywhere in the chain
// silently breaks tenancy.
func TestTenantClaimRoundTrip(t *testing.T) {
	in := Claims{Tenant: "01TENANTULID", SerialNumber: testIDCodeLV(1)}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}

	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["tenant"] != "01TENANTULID" {
		t.Fatalf("wire tenant = %v (must serialise as the `tenant` claim)", wire["tenant"])
	}

	var out Claims
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Tenant != "01TENANTULID" {
		t.Fatalf("parsed tenant = %q", out.Tenant)
	}

	m := out.ToUserClaims()
	if got := m[ClaimTenant]; len(got) != 1 || got[0] != "01TENANTULID" {
		t.Fatalf("user-claim tenant = %v (resource services read it via ClaimValue)", got)
	}
}

// A token without a tenant must not grow an empty claim — deployments without
// a membership register stay byte-identical.
func TestNoTenantMeansNoClaim(t *testing.T) {
	raw, err := json.Marshal(Claims{SerialNumber: testIDCodeLV(1)})
	if err != nil {
		t.Fatal(err)
	}

	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, present := wire["tenant"]; present {
		t.Fatal("an empty tenant must be omitted from the wire form")
	}

	var out Claims
	_ = json.Unmarshal(raw, &out)
	if _, present := out.ToUserClaims()[ClaimTenant]; present {
		t.Fatal("an empty tenant must not appear in the user-claim map")
	}
}

// userOf builds the user a resource service reads, the way the inbound
// middleware does: wire JSON → Claims → the azugo claim map.
func userOf(t *testing.T, in Claims) *user.Basic {
	t.Helper()

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Claims
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}

	return user.New(out.ToUserClaims())
}

// A token minted on behalf of a person names, in `act`, the service acting for
// them, nesting whoever acted before it. The chain survives to the claim map a
// resource service reads, the one presenting the token first, and that service
// is the acting client — never the person, whose subject the token keeps.
func TestTheActingChainReachesTheResourceService(t *testing.T) {
	u := userOf(t, Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "sub:01PERSON"},
		Tenant:           "01TENANTULID",
		Act:              &Actor{Subject: "svc:portal-api", Act: &Actor{Subject: "svc:gateway"}},
	})

	if got := u.Claim(ClaimAct); len(got) != 2 || got[0] != "svc:portal-api" || got[1] != "svc:gateway" {
		t.Fatalf("user-claim act = %v (the chain, the one presenting the token first)", got)
	}
	if got := ActingClient(u); got != "svc:portal-api" {
		t.Fatalf("ActingClient = %q, want the service presenting the token", got)
	}
	if u.ID() != "sub:01PERSON" {
		t.Fatalf("the subject stays the person: %q", u.ID())
	}
}

// A service's own token is presented by that service.
func TestAServicesOwnTokenIsPresentedByItself(t *testing.T) {
	u := userOf(t, Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "svc:portal-api"},
		ClientID:         "svc:portal-api",
	})

	if got := ActingClient(u); got != "svc:portal-api" {
		t.Fatalf("ActingClient = %q, want the service itself", got)
	}
}

// A person's own token names no acting client, and grows no `act` claim; nor
// does a token whose actor names nobody. Nobody is guessed.
func TestAPersonsOwnTokenHasNoActingClient(t *testing.T) {
	for _, c := range []struct {
		name string
		in   Claims
	}{
		{"a person's own token", Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "sub:01PERSON"}, SerialNumber: testIDCodeLV(1)}},
		{"an actor naming nobody", Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "sub:01PERSON"}, Act: &Actor{}}},
	} {
		u := userOf(t, c.in)
		if got := u.Claim(ClaimAct); len(got) != 0 {
			t.Fatalf("%s: an act claim appeared: %v", c.name, got)
		}
		if got := ActingClient(u); got != "" {
			t.Fatalf("%s: ActingClient = %q, want none", c.name, got)
		}
	}
	if got := ActingClient(nil); got != "" {
		t.Fatalf("no user: ActingClient = %q", got)
	}
}
