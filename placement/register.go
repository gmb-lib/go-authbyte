package placement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// The levels the membership register checks, one per call: reading what the
// roles carry is a different authority from reporting roles in use.
const (
	ScopeDefinitions = "membership:definitions"
	ScopePlacements  = "membership:placements"
)

// Doer makes a call as the service itself, a member of the tenant it names.
// [authclient.Client] is one.
type Doer interface {
	DoServiceForTenant(ctx context.Context, audience, scope, tenant, method, fullURL string,
		reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
}

// Register is the membership register reached over the network: the [Source] a
// service uses in production.
type Register struct {
	do       Doer
	base     string
	audience string
	groups   []string
}

// NewRegister answers a Source over the register at baseURL (its root, without
// the API path), reached as the service itself for audience. groups are the
// scope groups whose permissions the service checks; every other permission a
// role carries is left out of the copy.
func NewRegister(do Doer, baseURL, audience string, groups ...string) (*Register, error) {
	if do == nil {
		return nil, errors.New("placement: a client is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("placement: %q is not an absolute address", baseURL)
	}
	if audience == "" {
		return nil, errors.New("placement: the register's audience is required")
	}
	if len(groups) == 0 {
		return nil, errors.New("placement: name at least one scope group to copy")
	}
	for _, g := range groups {
		if g == "" || strings.ContainsAny(g, "/:") {
			return nil, fmt.Errorf("placement: %q is not a scope group", g)
		}
	}

	return &Register{
		do:       do,
		base:     strings.TrimRight(baseURL, "/"),
		audience: audience,
		groups:   slices.Clone(groups),
	}, nil
}

// definitionsBody is the register's answer: every role of the tenant with every
// permission it carries there.
type definitionsBody struct {
	Roles []struct {
		ID          string   `json:"id"`
		Seed        string   `json:"seed"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	} `json:"roles"`
}

// Definitions implements Source.
func (r *Register) Definitions(ctx context.Context, tenant, version string) (Definitions, bool, error) {
	h := http.Header{"Accept": {"application/json"}}
	if version != "" {
		h.Set("If-None-Match", version)
	}

	res, err := r.do.DoServiceForTenant(ctx, r.audience, ScopeDefinitions, tenant, http.MethodGet,
		r.tenantURL(tenant, "role-definitions"), h, nil)
	if err != nil {
		return Definitions{}, false, err
	}

	switch res.StatusCode {
	case http.StatusNotModified:
		return Definitions{}, false, nil
	case http.StatusOK:
	default:
		return Definitions{}, false, refused(res)
	}

	etag := res.Header.Get("ETag")
	if etag == "" {
		return Definitions{}, false, errors.New("placement: the register answered the roles without a version")
	}

	var body definitionsBody
	if err := json.Unmarshal(res.Body, &body); err != nil {
		return Definitions{}, false, fmt.Errorf("placement: read the roles: %w", err)
	}

	d := Definitions{Version: etag, Roles: make([]Role, 0, len(body.Roles))}
	for _, role := range body.Roles {
		if role.ID == "" {
			return Definitions{}, false, errors.New("placement: the register answered a role with no id")
		}
		d.Roles = append(d.Roles, Role{
			ID:          role.ID,
			Seed:        role.Seed,
			Name:        role.Name,
			Description: role.Description,
			Keys:        r.own(role.Permissions),
		})
	}

	return d, true, nil
}

// own keeps the permissions of the groups this service checks, sorted.
func (r *Register) own(perms []string) []string {
	keys := []string{}
	for _, p := range perms {
		group, _, ok := strings.Cut(p, "/")
		if ok && slices.Contains(r.groups, group) {
			keys = append(keys, p)
		}
	}
	slices.Sort(keys)

	return slices.Compact(keys)
}

// Report implements Source.
func (r *Register) Report(ctx context.Context, tenant string, counts map[string]int) ([]string, error) {
	if counts == nil {
		counts = map[string]int{}
	}
	payload, err := json.Marshal(map[string]any{"placements": counts})
	if err != nil {
		return nil, err
	}

	h := http.Header{"Accept": {"application/json"}, "Content-Type": {"application/json"}}
	res, err := r.do.DoServiceForTenant(ctx, r.audience, ScopePlacements, tenant, http.MethodPut,
		r.tenantURL(tenant, "role-placements"), h, payload)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, refused(res)
	}

	var body struct {
		Unknown []string `json:"unknown"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		return nil, fmt.Errorf("placement: read the report's answer: %w", err)
	}

	return body.Unknown, nil
}

func (r *Register) tenantURL(tenant, what string) string {
	return r.base + "/api/v1/tenants/" + url.PathEscape(tenant) + "/" + what
}

// refused is an answer that is not the one asked for, typed as the rest of the
// library types an answer, so a caller can tell a refusal from an outage.
func refused(res *authclient.BackgroundResponse) error {
	return &authclient.Error{Hop: authclient.HopResource, Status: res.StatusCode, Body: string(res.Body)}
}
