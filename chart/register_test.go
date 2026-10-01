package chart

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-authbyte/placement"
)

// fakeDoer answers one prepared response and records the call.
type fakeDoer struct {
	res *authclient.BackgroundResponse
	err error

	audience, scope, tenant, method, url string
	header                               http.Header
}

func (f *fakeDoer) DoServiceForTenant(_ context.Context, audience, scope, tenant, method, fullURL string,
	h http.Header, _ []byte,
) (*authclient.BackgroundResponse, error) {
	f.audience, f.scope, f.tenant, f.method, f.url, f.header = audience, scope, tenant, method, fullURL, h

	return f.res, f.err
}

func register(t *testing.T, d placement.Doer) *Register {
	t.Helper()
	r, err := NewRegister(d, "http://membership:8080/", "membership")
	qt.Assert(t, qt.IsNil(err))

	return r
}

func ok(body string) *authclient.BackgroundResponse {
	return &authclient.BackgroundResponse{StatusCode: http.StatusOK, Header: http.Header{"Etag": {`"v1"`}}, Body: []byte(body)}
}

func TestNewRegisterRefusesWhatCannotWork(t *testing.T) {
	d := &fakeDoer{}
	_, err := NewRegister(nil, "http://r", "a")
	qt.Check(t, qt.ErrorMatches(err, `.*a client is required`))
	_, err = NewRegister(d, "membership", "a")
	qt.Check(t, qt.ErrorMatches(err, `.*not an absolute address`))
	_, err = NewRegister(d, "http://r", "")
	qt.Check(t, qt.ErrorMatches(err, `.*audience is required`))
}

func TestChartIsAskedAsTheServiceForTheTenant(t *testing.T) {
	d := &fakeDoer{res: ok(`{"below":{}}`)}

	_, _, err := register(t, d).Chart(context.Background(), "t 1", `"v0"`)

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(d.audience, "membership"))
	qt.Check(t, qt.Equals(d.scope, ScopeChart))
	qt.Check(t, qt.Equals(d.tenant, "t 1"))
	qt.Check(t, qt.Equals(d.method, http.MethodGet))
	qt.Check(t, qt.Equals(d.url, "http://membership:8080/api/v1/tenants/t%201/chart"))
	qt.Check(t, qt.Equals(d.header.Get("If-None-Match"), `"v0"`))
}

func TestChartReadsWhoIsBelowWhomCleanedAndSorted(t *testing.T) {
	d := &fakeDoer{res: ok(`{"below":{"sub:a":["sub:c","sub:b","sub:c","","sub:a"],"sub:b":[],"sub:c":["sub:d"]}}`)}

	got, changed, err := register(t, d).Chart(context.Background(), "t1", "")

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(changed))
	qt.Check(t, qt.Equals(got.Version, `"v1"`))
	// A person is never below themselves, a repeat counts once, and a person with
	// nobody below has no entry.
	qt.Check(t, qt.DeepEquals(got.Below, map[string][]string{"sub:a": {"sub:b", "sub:c"}, "sub:c": {"sub:d"}}))
}

func TestChartReadsA304AsUnchanged(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusNotModified}}

	_, changed, err := register(t, d).Chart(context.Background(), "t1", `"abc"`)

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(changed))
}

func TestChartRefusedIsTyped(t *testing.T) {
	d := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusForbidden, Body: []byte(`{"title":"no"}`)}}

	_, _, err := register(t, d).Chart(context.Background(), "t1", "")

	var refusedErr *authclient.Error
	qt.Assert(t, qt.IsTrue(errors.As(err, &refusedErr)))
	qt.Check(t, qt.Equals(refusedErr.Status, http.StatusForbidden))
}

func TestChartWithoutAVersionOrWithABadBodyFails(t *testing.T) {
	noTag := &fakeDoer{res: &authclient.BackgroundResponse{StatusCode: http.StatusOK, Body: []byte(`{"below":{}}`)}}
	_, _, err := register(t, noTag).Chart(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `.*without a version`))

	bad := &fakeDoer{res: ok(`not json`)}
	_, _, err = register(t, bad).Chart(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `.*read the chart.*`))

	noSubject := &fakeDoer{res: ok(`{"below":{"":["sub:b"]}}`)}
	_, _, err = register(t, noSubject).Chart(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `.*no subject`))

	down := &fakeDoer{err: errors.New("dial tcp: refused")}
	_, _, err = register(t, down).Chart(context.Background(), "t1", "")
	qt.Check(t, qt.ErrorMatches(err, `dial tcp: refused`))
}
