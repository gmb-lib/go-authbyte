package placement

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// fakeDoer answers one prepared response and records the call.
type fakeDoer struct {
	res *authclient.BackgroundResponse
	err error

	audience, scope, tenant, method, url string
	header                               http.Header
	body                                 []byte
}

func (f *fakeDoer) DoServiceForTenant(_ context.Context, audience, scope, tenant, method, fullURL string,
	h http.Header, body []byte,
) (*authclient.BackgroundResponse, error) {
	f.audience, f.scope, f.tenant, f.method, f.url, f.header, f.body = audience, scope, tenant, method, fullURL, h, body

	return f.res, f.err
}

func register(t *testing.T, d Doer) *Register {
	t.Helper()
	r, err := NewRegister(d, "http://membership:8080/", "membership", "projects")
	qt.Assert(t, qt.IsNil(err))

	return r
}

func TestNewRegisterRefusesWhatCannotWork(t *testing.T) {
	d := &fakeDoer{}
	for _, tc := range []struct {
		name     string
		doer     Doer
		base     string
		audience string
		groups   []string
		want     string
	}{
		{"no client", nil, "http://r", "a", []string{"g"}, `.*a client is required`},
		{"relative address", d, "membership", "a", []string{"g"}, `.*not an absolute address`},
		{"no audience", d, "http://r", "", []string{"g"}, `.*audience is required`},
		{"no groups", d, "http://r", "a", nil, `.*at least one scope group.*`},
		{"a key, not a group", d, "http://r", "a", []string{"projects/task"}, `.*is not a scope group`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRegister(tc.doer, tc.base, tc.audience, tc.groups...)
			qt.Check(t, qt.ErrorMatches(err, tc.want))
		})
	}
}

func TestDefinitionsKeepOnlyThisServicesPermissions(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Etag": {`"abc"`}},
		Body: []byte(`{"tenantId":"t/1","roles":[{"id":"r1","name":"Manager","description":"Everything",` +
			`"permissions":["workforce/person:view","projects/task:edit","projects/project:view","projects/task:edit"]}]}`),
	}}

	got, changed, err := register(t, d).Definitions(context.Background(), "t/1", "")

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(changed))
	qt.Check(t, qt.DeepEquals(got, Definitions{Version: `"abc"`, Roles: []Role{{
		ID: "r1", Name: "Manager", Description: "Everything",
		Keys: []string{"projects/project:view", "projects/task:edit"},
	}}}))
	qt.Check(t, qt.Equals(d.url, "http://membership:8080/api/v1/tenants/t%2F1/role-definitions"))
	qt.Check(t, qt.Equals(d.method, http.MethodGet))
	qt.Check(t, qt.Equals(d.scope, ScopeDefinitions))
	qt.Check(t, qt.Equals(d.tenant, "t/1"))
	qt.Check(t, qt.Equals(d.audience, "membership"))
	qt.Check(t, qt.Equals(d.header.Get("If-None-Match"), ""))
}

func TestDefinitionsSendTheVersionHeldAndReadA304AsUnchanged(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusNotModified}}

	_, changed, err := register(t, d).Definitions(context.Background(), "t1", `"abc"`)

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(changed))
	qt.Check(t, qt.Equals(d.header.Get("If-None-Match"), `"abc"`))
}

func TestDefinitionsRefusedAreTyped(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusForbidden, Body: []byte(`{"title":"no"}`)}}

	_, _, err := register(t, d).Definitions(context.Background(), "t1", "")

	var refusedErr *authclient.Error
	qt.Assert(t, qt.IsTrue(errors.As(err, &refusedErr)))
	qt.Check(t, qt.Equals(refusedErr.Status, http.StatusForbidden))
	qt.Check(t, qt.Equals(refusedErr.Body, `{"title":"no"}`))
}

func TestDefinitionsWithoutAVersionOrWithABadBodyFail(t *testing.T) {
	noTag := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusOK, Body: []byte(`{"roles":[]}`)}}
	_, _, err := register(t, noTag).Definitions(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `.*without a version`))

	bad := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusOK,
		Header: http.Header{"Etag": {`"x"`}}, Body: []byte(`not json`)}}
	_, _, err = register(t, bad).Definitions(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `.*read the roles.*`))

	noID := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusOK,
		Header: http.Header{"Etag": {`"x"`}}, Body: []byte(`{"roles":[{"name":"Worker"}]}`)}}
	_, _, err = register(t, noID).Definitions(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `.*a role with no id`))

	down := &fakeDoer{err: errors.New("dial tcp: refused")}
	_, _, err = register(t, down).Definitions(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `dial tcp: refused`))
}

func TestReportSendsTheWholeSetAndReadsTheUnknown(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusOK, Body: []byte(`{"unknown":["gone"]}`)}}

	unknown, err := register(t, d).Report(context.Background(), "t1", map[string]int{"r1": 3, "gone": 1})

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(unknown, []string{"gone"}))
	qt.Check(t, qt.Equals(d.method, http.MethodPut))
	qt.Check(t, qt.Equals(d.scope, ScopePlacements))
	qt.Check(t, qt.Equals(d.url, "http://membership:8080/api/v1/tenants/t1/role-placements"))
	qt.Check(t, qt.Equals(d.header.Get("Content-Type"), "application/json"))

	var sent map[string]map[string]int
	qt.Assert(t, qt.IsNil(json.Unmarshal(d.body, &sent)))
	qt.Check(t, qt.DeepEquals(sent, map[string]map[string]int{"placements": {"r1": 3, "gone": 1}}))
}

func TestReportOfNothingIsAnEmptySet(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusOK, Body: []byte(`{"unknown":[]}`)}}

	_, err := register(t, d).Report(context.Background(), "t1", nil)

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(d.body), `{"placements":{}}`))
}

func TestReportRefusedIsTyped(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusBadRequest, Body: []byte(`bad`)}}

	_, err := register(t, d).Report(context.Background(), "t1", map[string]int{"r1": 1})

	var refusedErr *authclient.Error
	qt.Assert(t, qt.IsTrue(errors.As(err, &refusedErr)))
	qt.Check(t, qt.Equals(refusedErr.Status, http.StatusBadRequest))

	down := &fakeDoer{err: errors.New("timeout")}
	_, err = register(t, down).Report(context.Background(), "t1", nil)
	qt.Check(t, qt.ErrorMatches(err, `timeout`))

	garbled := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusOK, Body: []byte(`{`)}}
	_, err = register(t, garbled).Report(context.Background(), "t1", nil)
	qt.Check(t, qt.ErrorMatches(err, `.*read the report's answer.*`))
}

// An *authclient.Client is a Doer, so a service passes the client it already has.
var _ Doer = (*authclient.Client)(nil)
