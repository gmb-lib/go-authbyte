package permissions

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

func setWithLevels(t *testing.T, key string) *Set {
	t.Helper()
	s, err := New(key, "Service "+key, []Permission{valid("task", "view")})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(s.AddLevels(
		Rung{Group: key, Level: "read", Description: "Read everything"},
		Rung{Group: key, Level: "write"},
	)))

	return s
}

type declared struct {
	Services []struct {
		Key         string            `json:"key"`
		DisplayName string            `json:"displayName"`
		Roles       []Rung            `json:"roles"`
		Permissions []json.RawMessage `json:"permissions"`
	} `json:"services"`
}

func TestDeclarationIsTheSameBytesEveryTimeAndCarriesLevelsUnderTheirKey(t *testing.T) {
	a, b := setWithLevels(t, "projects"), setWithLevels(t, "authority")
	first, err := Declaration(a, b)
	qt.Assert(t, qt.IsNil(err))
	for range 5 {
		again, err := Declaration(a, b)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(string(again), string(first)))
	}

	var doc declared
	qt.Assert(t, qt.IsNil(json.Unmarshal(first, &doc)))
	qt.Assert(t, qt.Equals(len(doc.Services), 2))
	qt.Assert(t, qt.Equals(doc.Services[0].Key, "projects"))
	qt.Assert(t, qt.Equals(doc.Services[1].Key, "authority"))
	qt.Assert(t, qt.DeepEquals(doc.Services[0].Roles, []Rung{
		{Group: "projects", Level: "read", Description: "Read everything"},
		{Group: "projects", Level: "write"},
	}))
	qt.Assert(t, qt.Equals(len(doc.Services[1].Permissions), 1))
	// A level with no description carries no description member.
	qt.Assert(t, qt.IsTrue(strings.Contains(string(first), `"level": "write"`+"\n")))
}

func TestDeclarationLeavesRolesOutWhenThereAreNoLevelsAndKeepsPermissions(t *testing.T) {
	empty, err := New("authority", "Authority")
	qt.Assert(t, qt.IsNil(err))
	doc, err := Declaration(empty)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(strings.Contains(string(doc), `"roles"`)))
	qt.Assert(t, qt.IsTrue(strings.Contains(string(doc), `"permissions": []`)))
}

func TestDeclarationRefusesTwoSetsUnderOneKey(t *testing.T) {
	_, err := Declaration(setWithLevels(t, "projects"), setWithLevels(t, "projects"))
	qt.Assert(t, qt.ErrorMatches(err, `.*projects is in the declaration twice`))
	_, err = Declaration(nil)
	qt.Assert(t, qt.IsNotNil(err))
}

func TestServiceKeysFollowTheOrderGiven(t *testing.T) {
	keys := ServiceKeys(setWithLevels(t, "projects"), setWithLevels(t, "authority"))
	qt.Assert(t, qt.DeepEquals(keys, []string{"projects", "authority"}))
}

func TestAddLevelsRefusesBadShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    []Rung
		says string
	}{
		{"an upper-case group", []Rung{{Group: "Projects", Level: "read"}}, "group"},
		{"a colon in a group", []Rung{{Group: "a:b", Level: "read"}}, "group"},
		{"a slash in a level", []Rung{{Group: "projects", Level: "a/b"}}, "level"},
		{"a space in a level", []Rung{{Group: "projects", Level: "read all"}}, "level"},
		{"an empty level", []Rung{{Group: "projects"}}, "level"},
		{"an empty group", []Rung{{Level: "read"}}, "group"},
		{"a description with surrounding space", []Rung{{Group: "projects", Level: "read", Description: " x"}}, "description"},
		{"a level named twice", []Rung{{Group: "projects", Level: "read"}, {Group: "projects", Level: "read"}}, "twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := MustNew("projects", "Projects")
			err := s.AddLevels(tc.r...)
			qt.Assert(t, qt.IsNotNil(err))
			qt.Assert(t, qt.IsTrue(strings.Contains(err.Error(), tc.says)))
			qt.Assert(t, qt.HasLen(s.Levels(), 0))
		})
	}

	s := setWithLevels(t, "projects")
	err := s.AddLevels(Rung{Group: "projects", Level: "read"})
	qt.Assert(t, qt.ErrorMatches(err, `.*declared twice`))
	qt.Assert(t, qt.HasLen(s.Levels(), 2))
}

func TestSectionCarriesLevelsWhenTheSetHasThem(t *testing.T) {
	doc, err := setWithLevels(t, "projects").Section()
	qt.Assert(t, qt.IsNil(err))
	one, err := Declaration(setWithLevels(t, "projects"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(doc), string(one)))
	qt.Assert(t, qt.IsTrue(strings.Contains(string(doc), `"roles"`)))
}
