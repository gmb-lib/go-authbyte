package claims

import (
	"encoding/json"
	"testing"
)

// The tenant claim must survive the full path: struct → wire JSON → struct →
// the azugo claim map a resource service reads it from. Multi-tenant services
// scope every operation by this value, so dropping it anywhere in the chain
// silently breaks tenancy.
func TestTenantClaimRoundTrip(t *testing.T) {
	in := Claims{Tenant: "01TENANTULID", SerialNumber: "PNOLV-111111-11111"}

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
	raw, err := json.Marshal(Claims{SerialNumber: "PNOLV-111111-11111"})
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
