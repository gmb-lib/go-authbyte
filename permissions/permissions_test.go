package permissions

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

func valid(feature, act string) Permission {
	return Permission{Feature: feature, Act: act, Description: "Do " + act, Class: Ordinary, Plane: Object}
}

// A list the membership register would refuse is refused when the Set is built,
// naming the permission, rather than at a deployment's first apply.
func TestNewRefusesWhatTheRegisterRefuses(t *testing.T) {
	with := func(change func(*Permission)) []Permission {
		p := valid("task", "view")
		change(&p)

		return []Permission{p}
	}
	for _, tc := range []struct {
		name string
		list []Permission
		says string
	}{
		{"a capitalised feature", with(func(p *Permission) { p.Feature = "Task" }), "feature"},
		{"an empty feature segment", with(func(p *Permission) { p.Feature = "task//comment" }), "feature"},
		{"a trailing slash", with(func(p *Permission) { p.Feature = "task/" }), "feature"},
		{"a colon in a feature", with(func(p *Permission) { p.Feature = "task:comment" }), "feature"},
		{"a space in a feature", with(func(p *Permission) { p.Feature = "task comment" }), "feature"},
		{"a hyphen in an act", with(func(p *Permission) { p.Act = "delete-own" }), "act"},
		{"a comma in an act", with(func(p *Permission) { p.Act = "view,edit" }), "act"},
		{"no act", with(func(p *Permission) { p.Act = "" }), "act"},
		{"no description", with(func(p *Permission) { p.Description = "" }), "description"},
		{"a description with surrounding space", with(func(p *Permission) { p.Description = " Do it" }), "description"},
		{"an unknown class", with(func(p *Permission) { p.Class = "admin" }), "class"},
		{"no class", with(func(p *Permission) { p.Class = "" }), "class"},
		{"an unknown plane", with(func(p *Permission) { p.Plane = "project" }), "plane"},
		{"no plane", with(func(p *Permission) { p.Plane = "" }), "plane"},
		{"an upper-case language tag", with(func(p *Permission) { p.Labels = map[string]string{"LV": "Skatīt"} }), "language tag"},
		{"a language name for a tag", with(func(p *Permission) { p.Labels = map[string]string{"latvian": "Skatīt"} }), "language tag"},
		{"an empty label", with(func(p *Permission) { p.Labels = map[string]string{"lv": " "} }), "label"},
		{"a label with surrounding space", with(func(p *Permission) { p.Labels = map[string]string{"lv": "Skatīt "} }), "label"},
		{"a label too long", with(func(p *Permission) { p.Labels = map[string]string{"lv": strings.Repeat("a", 257)} }), "label"},
		{"a permission declared twice", []Permission{valid("task", "view"), valid("task", "view")}, "declared twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("projects", "Projects", tc.list)
			qt.Assert(t, qt.IsNotNil(err))
			qt.Check(t, qt.StringContains(err.Error(), tc.says))
			qt.Check(t, qt.StringContains(err.Error(), "projects/"))
		})
	}

	_, err := New("Projects", "Projects", []Permission{valid("task", "view")})
	qt.Check(t, qt.ErrorMatches(err, `.*service key "Projects".*`))
	_, err = New("projects", " ", []Permission{valid("task", "view")})
	qt.Check(t, qt.ErrorMatches(err, `.*no display name.*`))
	qt.Check(t, qt.PanicMatches(func() { MustNew("projects", "Projects", []Permission{valid("Task", "view")}) }, `.*feature.*`))
}

// A library's permissions join the service's own, under the service's key, and a
// permission the library also declares is a duplicate like any other.
func TestContributionsJoinUnderTheServiceKey(t *testing.T) {
	own := []Permission{valid("task", "view")}
	library := []Permission{valid("config", "apply")}

	s, err := New("projects", "Projects", own, library)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(s.List(), 2))
	qt.Check(t, qt.Equals(s.Declared("config", "apply").String(), "projects/config:apply"))

	_, err = New("projects", "Projects", own, []Permission{valid("task", "view")})
	qt.Check(t, qt.ErrorMatches(err, `.*projects/task:view is declared twice.*`))
}

// A check naming an act the Set does not declare stops the service, naming it.
func TestDeclaredStopsOnAnUndeclaredCheck(t *testing.T) {
	s := MustNew("projects", "Projects", []Permission{valid("task", "view")})

	qt.Check(t, qt.Equals(s.Declared("task", "view").String(), "projects/task:view"))
	qt.Check(t, qt.PanicMatches(func() { s.Declared("task", "teleport") }, `.*projects/task:teleport is checked but not declared`))
	qt.Check(t, qt.PanicMatches(func() { s.Declared("task/attachment", "view") }, `.*projects/task/attachment:view is checked but not declared`))
}

type scopes map[string]bool

func (s scopes) HasScopeLevel(group, level string) bool { return s[group+":"+level] }

// Holding a permission is an exact match: nesting grants nothing, an act on a
// feature implies no other act, and a ladder level is not a permission.
func TestHoldingIsAnExactMatch(t *testing.T) {
	s := MustNew("projects", "Projects", []Permission{
		valid("task", "delete"), valid("task/attachment", "delete"), valid("task", "view"),
	})
	onTask := scopes{"projects/task:delete": true}

	qt.Check(t, qt.IsTrue(s.Declared("task", "delete").HeldBy(onTask)))
	qt.Check(t, qt.IsFalse(s.Declared("task/attachment", "delete").HeldBy(onTask)))
	qt.Check(t, qt.IsFalse(s.Declared("task", "view").HeldBy(onTask)))
	qt.Check(t, qt.IsFalse(s.Declared("task", "view").HeldBy(scopes{"projects:read": true})))
	qt.Check(t, qt.IsFalse(s.Declared("task", "delete").HeldBy(scopes{"other/task:delete": true})))
}

// Any declared permission makes a caller a member, a retired one included:
// it keeps working for the roles that hold it.
func TestHeldAnyCountsEveryDeclaredPermission(t *testing.T) {
	old := valid("task", "archive")
	old.Retired = true
	s := MustNew("projects", "Projects", []Permission{valid("task", "view"), old})

	qt.Check(t, qt.IsTrue(s.HeldAny(scopes{"projects/task:view": true})))
	qt.Check(t, qt.IsTrue(s.HeldAny(scopes{"projects/task:archive": true})))
	qt.Check(t, qt.IsFalse(s.HeldAny(scopes{"projects:read": true, "other/task:view": true})))
	qt.Check(t, qt.IsFalse(s.HeldAny(scopes{})))
}

// A label is the language's own, then its primary language's, then the
// description.
func TestLabelFallsBackToTheDescription(t *testing.T) {
	p := Permission{Description: "Remove any file", Labels: map[string]string{"lv": "Noņemt jebkuru failu", "pt-BR": "Remover"}}

	qt.Check(t, qt.Equals(p.Label("lv"), "Noņemt jebkuru failu"))
	qt.Check(t, qt.Equals(p.Label("lv-LV"), "Noņemt jebkuru failu"))
	qt.Check(t, qt.Equals(p.Label("pt-BR"), "Remover"))
	qt.Check(t, qt.Equals(p.Label("en"), "Remove any file"))
	qt.Check(t, qt.Equals(p.Label(""), "Remove any file"))
	qt.Check(t, qt.Equals(Permission{Description: "Remove any file"}.Label("lv"), "Remove any file"))
}

// The register document is the service under its key with its permissions, and
// only the properties the register reads: labels and the retired mark only
// where they say something, labels in a fixed order.
func TestSectionIsTheRegisterDocument(t *testing.T) {
	gone := Permission{Feature: "task", Act: "archive", Description: "Archive a task", Class: Ordinary, Plane: Object, Retired: true}
	s := MustNew("projects", "Project and workflow engine", []Permission{
		{Feature: "project", Act: "create", Description: "Register a project", Class: Ordinary, Plane: Tenant,
			Labels: map[string]string{"lv": "Reģistrēt projektu", "de": "Projekt anlegen"}},
		{Feature: "setup", Act: "import", Description: "Apply a configuration file", Class: TenantConfiguration, Plane: Tenant},
		gone,
	})

	raw, err := s.Section()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(raw), `{
  "services": [
    {
      "key": "projects",
      "displayName": "Project and workflow engine",
      "permissions": [
        {
          "feature": "project",
          "act": "create",
          "description": "Register a project",
          "class": "ordinary",
          "plane": "tenant",
          "labels": {
            "de": "Projekt anlegen",
            "lv": "Reģistrēt projektu"
          }
        },
        {
          "feature": "setup",
          "act": "import",
          "description": "Apply a configuration file",
          "class": "tenantConfiguration",
          "plane": "tenant"
        },
        {
          "feature": "task",
          "act": "archive",
          "description": "Archive a task",
          "class": "ordinary",
          "plane": "object",
          "retired": true
        }
      ]
    }
  ]
}`))
}

// What the Set answers is its own copy: changing it changes nothing declared.
func TestListAndLookupAnswerCopies(t *testing.T) {
	p := valid("task", "view")
	p.Labels = map[string]string{"lv": "Skatīt"}
	own := []Permission{p}
	s := MustNew("projects", "Projects", own)

	own[0].Labels["lv"] = "changed by the caller"
	s.List()[0].Labels["lv"] = "changed through List"
	got, ok := s.Lookup("task", "view")
	qt.Assert(t, qt.IsTrue(ok))
	got.Labels["lv"] = "changed through Lookup"

	again, _ := s.Lookup("task", "view")
	qt.Check(t, qt.Equals(again.Labels["lv"], "Skatīt"))
	_, ok = s.Lookup("task", "edit")
	qt.Check(t, qt.IsFalse(ok))
}
