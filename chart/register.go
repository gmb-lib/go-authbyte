package chart

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
	"github.com/gmb-lib/go-authbyte/placement"
)

// ScopeChart is the level the membership register checks to answer a tenant's
// chart: reading who is below whom is a different authority from reading roles.
const ScopeChart = "membership:chart"

// Register is the membership register reached over the network: the [Source] a
// service uses in production.
type Register struct {
	do       placement.Doer
	base     string
	audience string
}

// NewRegister answers a Source over the register at baseURL (its root, without
// the API path), reached as the service itself for audience.
func NewRegister(do placement.Doer, baseURL, audience string) (*Register, error) {
	if do == nil {
		return nil, errors.New("chart: a client is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("chart: %q is not an absolute address", baseURL)
	}
	if audience == "" {
		return nil, errors.New("chart: the register's audience is required")
	}

	return &Register{do: do, base: strings.TrimRight(baseURL, "/"), audience: audience}, nil
}

// chartBody is the register's answer: for each person, everyone below them.
type chartBody struct {
	Below map[string][]string `json:"below"`
}

// Chart implements Source.
func (r *Register) Chart(ctx context.Context, tenant, version string) (Chart, bool, error) {
	h := http.Header{"Accept": {"application/json"}}
	if version != "" {
		h.Set("If-None-Match", version)
	}

	res, err := r.do.DoServiceForTenant(ctx, r.audience, ScopeChart, tenant, http.MethodGet,
		r.base+"/api/v1/tenants/"+url.PathEscape(tenant)+"/chart", h, nil)
	if err != nil {
		return Chart{}, false, err
	}

	switch res.StatusCode {
	case http.StatusNotModified:
		return Chart{}, false, nil
	case http.StatusOK:
	default:
		return Chart{}, false, &authclient.Error{Hop: authclient.HopResource, Status: res.StatusCode, Body: string(res.Body)}
	}

	etag := res.Header.Get("ETag")
	if etag == "" {
		return Chart{}, false, errors.New("chart: the register answered the chart without a version")
	}

	var body chartBody
	if err := json.Unmarshal(res.Body, &body); err != nil {
		return Chart{}, false, fmt.Errorf("chart: read the chart: %w", err)
	}

	c := Chart{Version: etag, Below: make(map[string][]string, len(body.Below))}
	for subject, below := range body.Below {
		if subject == "" {
			return Chart{}, false, errors.New("chart: the register answered a position holder with no subject")
		}
		below = slices.DeleteFunc(slices.Clone(below), func(s string) bool { return s == "" || s == subject })
		slices.Sort(below)
		below = slices.Compact(below)
		if len(below) > 0 {
			c.Below[subject] = below
		}
	}

	return c, true, nil
}
