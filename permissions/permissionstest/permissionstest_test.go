package permissionstest

import (
	"fmt"
	"strings"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/permissions"
)

// recorder stands in for the test a service runs, keeping what the kit reports.
type recorder struct {
	testing.TB
	errs []string
}

type stopped struct{}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
	panic(stopped{})
}

// report runs a kit check against a recorder and answers what it reported.
func report(t *testing.T, check func(testing.TB)) []string {
	t.Helper()
	r := &recorder{TB: t}
	func() {
		defer func() {
			if v := recover(); v != nil {
				if _, ok := v.(stopped); !ok {
					panic(v)
				}
			}
		}()
		check(r)
	}()

	return r.errs
}

func perm(feature, act string) permissions.Permission {
	return permissions.Permission{Feature: feature, Act: act, Description: "Do " + act,
		Class: permissions.Ordinary, Plane: permissions.Object}
}

func ok(*azugo.Context) {}

// A service whose routes check exactly its list passes every rule.
func TestCheckPassesAServiceThatKeepsEveryRule(t *testing.T) {
	retired := perm("task", "archive")
	retired.Retired = true
	s := permissions.MustNew("projects", "Projects", []permissions.Permission{
		perm("task", "view"), perm("task", "deleteOwn"), perm("task", "delete"), retired,
	})
	g := s.Gate(nil)
	g.OneOf(permissions.Level{}, ok, s.Declared("task", "view"))
	g.OneOf(permissions.Level{}, ok, s.Declared("task", "deleteOwn"), s.Declared("task", "delete"))

	qt.Check(t, qt.HasLen(report(t, func(tb testing.TB) { Check(tb, s, g) }), 0))
}

// A declared permission no route accepts fails, and a retired one does not.
func TestDeclaredButUncheckedFails(t *testing.T) {
	retired := perm("task", "archive")
	retired.Retired = true
	s := permissions.MustNew("projects", "Projects", []permissions.Permission{perm("task", "view"), perm("task", "edit"), retired})
	g := s.Gate(nil)
	g.OneOf(permissions.Level{}, ok, s.Declared("task", "view"))

	errs := report(t, func(tb testing.TB) { DeclaredIsChecked(tb, s, g) })
	qt.Assert(t, qt.HasLen(errs, 1))
	qt.Check(t, qt.StringContains(errs[0], "projects/task:edit is declared but no route accepts it"))
}

// Routes spread over several Gates count together, and a route accepting
// another Set's permission fails.
func TestCheckedButUndeclaredFails(t *testing.T) {
	s := permissions.MustNew("projects", "Projects", []permissions.Permission{perm("task", "view"), perm("config", "apply")})
	other := permissions.MustNew("billing", "Billing", []permissions.Permission{perm("invoice", "view")})
	own, library := s.Gate(nil), s.Gate(nil)
	own.OneOf(permissions.Level{}, ok, s.Declared("task", "view"))
	library.OneOf(permissions.Level{}, ok, s.Declared("config", "apply"))

	qt.Check(t, qt.HasLen(report(t, func(tb testing.TB) { DeclaredIsChecked(tb, s, own, library) }), 0))

	own.OneOf(permissions.Level{}, ok, other.Declared("invoice", "view"))
	errs := report(t, func(tb testing.TB) { DeclaredIsChecked(tb, s, own, library) })
	qt.Assert(t, qt.HasLen(errs, 1))
	qt.Check(t, qt.StringContains(errs[0], "billing/invoice:view is accepted but not declared"))
}

// An act on your own work with no act on anybody's beside it fails.
func TestOwnWithoutAnyFails(t *testing.T) {
	s := permissions.MustNew("projects", "Projects", []permissions.Permission{perm("spentTime", "editOwn"), perm("spentTime", "own")})

	errs := report(t, func(tb testing.TB) { OwnBesideAny(tb, s) })
	qt.Assert(t, qt.HasLen(errs, 1))
	qt.Check(t, qt.StringContains(errs[0], "projects/spentTime:editOwn has no projects/spentTime:edit beside it"))
}

// The stop on an undeclared check is itself checked, on a Set whose first act
// happens to be the one the kit would try.
func TestUndeclaredCheckStops(t *testing.T) {
	s := permissions.MustNew("projects", "Projects", []permissions.Permission{perm("task", "neverDeclared")})

	qt.Check(t, qt.HasLen(report(t, func(tb testing.TB) { UndeclaredCheckStops(tb, s) }), 0))
}

// The register document passes for a Set, whatever its labels and retired marks.
func TestSectionPasses(t *testing.T) {
	labelled := perm("task", "view")
	labelled.Labels = map[string]string{"lv": "Skatīt uzdevumus"}
	retired := perm("task", "archive")
	retired.Retired = true
	s := permissions.MustNew("projects", "Projects", []permissions.Permission{labelled, retired})

	errs := report(t, func(tb testing.TB) { SectionIsTheRegisterDocument(tb, s) })
	qt.Check(t, qt.HasLen(errs, 0), qt.Commentf("%s", strings.Join(errs, "\n")))
}
