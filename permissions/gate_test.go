package permissions

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// gateApp serves routes guarded by one Gate; each request carries the caller's
// scopes in a header, and every refusal is recorded with what it said would
// have been enough.
type gateApp struct {
	t       *testing.T
	client  *azugo.TestClient
	refused []string
}

func newGateApp(t *testing.T, routes func(a *azugo.App, record func(*azugo.Context, string))) *gateApp {
	t.Helper()
	g := &gateApp{t: t}
	a := azugo.NewTestApp()
	a.Use(func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			ctx.SetUser(user.NewIdentity("sub:test", ctx.Header.Get("X-Scopes"), nil))
			next(ctx)
		}
	})
	routes(a.App, func(_ *azugo.Context, required string) { g.refused = append(g.refused, required) })
	a.Start(t)
	t.Cleanup(a.Stop)
	g.client = a.TestClient()

	return g
}

func ok(ctx *azugo.Context) { ctx.Text("ok") }

// status answers the status of a GET to path by a caller holding scopes.
func (g *gateApp) status(path, scopes string) int {
	g.t.Helper()
	resp, err := g.client.Get(path, g.client.WithHeader("X-Scopes", scopes))
	qt.Assert(g.t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	return resp.StatusCode()
}

func TestGateOneOfAllOfAndMember(t *testing.T) {
	s := MustNew("projects", "Projects", []Permission{
		valid("task", "view"), valid("task", "create"), valid("milestone", "manage"), valid("task", "changeStageOwn"),
		valid("task", "changeStage"),
	})
	var gate *Gate
	app := newGateApp(t, func(a *azugo.App, record func(*azugo.Context, string)) {
		gate = s.Gate(record)
		a.Get("/one", gate.OneOf(Levels("projects", "read"), ok, s.Declared("task", "view")))
		a.Get("/lanes", gate.OneOf(Levels("projects", "log", "write"), ok,
			s.Declared("task", "changeStageOwn"), s.Declared("task", "changeStage")))
		a.Get("/all", gate.AllOf(Levels("projects", "write"), ok, s.Declared("task", "create"), s.Declared("milestone", "manage")))
		a.Get("/member", gate.Member(Levels("projects", "read"), ok))
		a.Get("/no-ladder", gate.OneOf(Level{}, ok, s.Declared("task", "view")))
	})

	// One of: the level, or the permission.
	qt.Check(t, qt.Equals(app.status("/one", "projects:read"), 200))
	qt.Check(t, qt.Equals(app.status("/one", "projects/task:view"), 200))
	qt.Check(t, qt.Equals(app.status("/one", "projects:write projects/task:create"), 403))
	qt.Check(t, qt.Equals(app.status("/lanes", "projects:log"), 200))
	qt.Check(t, qt.Equals(app.status("/lanes", "projects:write"), 200))
	qt.Check(t, qt.Equals(app.status("/lanes", "projects/task:changeStageOwn"), 200))
	qt.Check(t, qt.Equals(app.status("/lanes", "projects:read"), 403))

	// All of: the level, or every permission named — one is not enough.
	qt.Check(t, qt.Equals(app.status("/all", "projects:write"), 200))
	qt.Check(t, qt.Equals(app.status("/all", "projects/task:create projects/milestone:manage"), 200))
	qt.Check(t, qt.Equals(app.status("/all", "projects/task:create"), 403))
	qt.Check(t, qt.Equals(app.status("/all", "projects/milestone:manage"), 403))

	// Member: the level, or any permission this service declares.
	qt.Check(t, qt.Equals(app.status("/member", "projects:read"), 200))
	qt.Check(t, qt.Equals(app.status("/member", "projects/milestone:manage"), 200))
	qt.Check(t, qt.Equals(app.status("/member", "other/task:view"), 403))
	qt.Check(t, qt.Equals(app.status("/member", ""), 403))

	// No ladder at all: only the permission opens it.
	qt.Check(t, qt.Equals(app.status("/no-ladder", "projects/task:view"), 200))
	qt.Check(t, qt.Equals(app.status("/no-ladder", "projects:read projects:admin"), 403))

	// Every refusal names what would have been enough.
	qt.Check(t, qt.DeepEquals(app.refused, []string{
		"projects:read or projects/task:view",
		"projects:log or projects:write or projects/task:changeStageOwn or projects/task:changeStage",
		"projects:write or all of projects/task:create projects/milestone:manage",
		"projects:write or all of projects/task:create projects/milestone:manage",
		"projects:read or any projects/ permission",
		"projects:read or any projects/ permission",
		"projects/task:view",
	}))

	// The Gate recorded what its routes accept, and nothing else.
	var accepted []string
	for _, p := range gate.Accepted() {
		accepted = append(accepted, p.String())
	}
	sort.Strings(accepted)
	qt.Check(t, qt.DeepEquals(accepted, []string{
		"projects/milestone:manage", "projects/task:changeStage", "projects/task:changeStageOwn",
		"projects/task:create", "projects/task:view",
	}))
}

// A level check across groups is the service's to write: here, the
// administering level in both of two modules.
func TestGateTakesAnyLevelCheck(t *testing.T) {
	s := MustNew("features", "Features", []Permission{valid("setup/kinds", "manage")})
	both := Level{
		Name: "workforce:admin and assets:admin",
		Holds: func(u Scopes) bool {
			return u.HasScopeLevel("workforce", "admin") && u.HasScopeLevel("assets", "admin")
		},
	}
	app := newGateApp(t, func(a *azugo.App, record func(*azugo.Context, string)) {
		a.Get("/apply", s.Gate(record).AllOf(both, ok, s.Declared("setup/kinds", "manage")))
	})

	qt.Check(t, qt.Equals(app.status("/apply", "workforce:admin assets:admin"), 200))
	qt.Check(t, qt.Equals(app.status("/apply", "workforce:admin"), 403))
	qt.Check(t, qt.Equals(app.status("/apply", "features/setup/kinds:manage"), 200))
	qt.Check(t, qt.DeepEquals(app.refused, []string{"workforce:admin and assets:admin or all of features/setup/kinds:manage"}))
}

// A refusal is answered 403 even when nobody records it.
func TestGateRefusesWithoutARecorder(t *testing.T) {
	s := MustNew("projects", "Projects", []Permission{valid("task", "view")})
	app := newGateApp(t, func(a *azugo.App, _ func(*azugo.Context, string)) {
		a.Get("/one", s.Gate(nil).OneOf(Level{}, ok, s.Declared("task", "view")))
	})

	qt.Check(t, qt.Equals(app.status("/one", ""), 403))
	qt.Check(t, qt.Equals(app.status("/one", "projects/task:view"), 200))
}

// The command prints the register document.
func TestCommandPrintsTheSection(t *testing.T) {
	s := MustNew("projects", "Projects", []Permission{valid("task", "view")})
	var out bytes.Buffer
	cmd := s.Command()
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	qt.Assert(t, qt.IsNil(cmd.Execute()))

	want, err := s.Section()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(out.String(), string(want)+"\n"))
	qt.Check(t, qt.Equals(cmd.Use, "permissions"))
	qt.Check(t, qt.IsTrue(strings.Contains(cmd.Short, "permissions")))
}
