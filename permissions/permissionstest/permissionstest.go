// Package permissionstest holds a service's routes against the permissions it
// declares, for use in the service's own tests.
package permissionstest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gmb-lib/go-authbyte/permissions"
)

// Check runs every rule a service's permissions must keep, given its Set and the
// Gates its routes were registered through (all of them, when libraries register
// routes of their own):
//
//   - declared is checked: every permission that is not retired is accepted by
//     some route — a permission nobody checks is a promise on a screen nobody keeps;
//   - checked is declared: every permission a route accepts belongs to this Set;
//   - a check naming an act the Set does not declare stops the service;
//   - an act on your own work ("editOwn") is declared beside the act on anybody's
//     ("edit"), so one can be given without the other;
//   - the register document carries every permission with exactly the properties
//     the membership register reads.
func Check(t testing.TB, set *permissions.Set, gates ...*permissions.Gate) {
	t.Helper()
	DeclaredIsChecked(t, set, gates...)
	UndeclaredCheckStops(t, set)
	OwnBesideAny(t, set)
	SectionIsTheRegisterDocument(t, set)
}

// DeclaredIsChecked fails unless the permissions the routes accept are exactly
// the Set's, retired ones aside: a retired permission may still be accepted,
// since it keeps working for the roles that hold it, and need not be.
func DeclaredIsChecked(t testing.TB, set *permissions.Set, gates ...*permissions.Gate) {
	t.Helper()
	accepted := map[string]bool{}
	for _, g := range gates {
		for _, p := range g.Accepted() {
			accepted[p.String()] = true
		}
	}
	declared := map[string]bool{}
	for _, p := range set.List() {
		name := p.Name(set.Service())
		declared[name] = true
		if !p.Retired && !accepted[name] {
			t.Errorf("%s is declared but no route accepts it", name)
		}
	}
	for name := range accepted {
		if !declared[name] {
			t.Errorf("%s is accepted but not declared", name)
		}
	}
}

// UndeclaredCheckStops fails unless naming an undeclared act panics, saying
// which permission it was.
func UndeclaredCheckStops(t testing.TB, set *permissions.Set) {
	t.Helper()
	feature := "undeclared"
	if list := set.List(); len(list) > 0 {
		feature = list[0].Feature
	}
	act := "neverDeclared"
	for {
		if _, ok := set.Lookup(feature, act); !ok {
			break
		}
		act += "X"
	}
	want := set.Service() + "/" + feature + ":" + act + " is checked but not declared"
	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("checking %s/%s:%s should stop the service", set.Service(), feature, act)

			return
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, want) {
			t.Errorf("the stop should name the permission: %s", msg)
		}
	}()
	set.Declared(feature, act)
}

// OwnBesideAny fails when an act ending in "Own" has no act for anybody's work
// beside it on the same feature.
func OwnBesideAny(t testing.TB, set *permissions.Set) {
	t.Helper()
	for _, p := range set.List() {
		anyAct, ok := strings.CutSuffix(p.Act, "Own")
		if !ok || anyAct == "" {
			continue
		}
		if _, found := set.Lookup(p.Feature, anyAct); !found {
			t.Errorf("%s has no %s beside it", p.Name(set.Service()), set.Service()+"/"+p.Feature+":"+anyAct)
		}
	}
}

// The properties the membership register reads on a declaration. It refuses any
// other rather than dropping it, so the document must carry no more.
var (
	required = []string{"feature", "act", "description", "class", "plane"}
	optional = []string{"labels", "retired", "seeds"}
)

// SectionIsTheRegisterDocument fails unless the Set renders as one service under
// its key, carrying every permission with only the properties the membership
// register reads.
func SectionIsTheRegisterDocument(t testing.TB, set *permissions.Set) {
	t.Helper()
	raw, err := set.Section()
	if err != nil {
		t.Fatalf("the section does not render: %v", err)
	}
	var doc struct {
		Services []struct {
			Key         string            `json:"key"`
			DisplayName string            `json:"displayName"`
			Permissions []json.RawMessage `json:"permissions"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the section is not a document: %v", err)
	}
	if len(doc.Services) != 1 || doc.Services[0].Key != set.Service() || doc.Services[0].DisplayName == "" {
		t.Fatalf("the section should carry exactly this service, named: %s", raw)
	}
	if got, want := len(doc.Services[0].Permissions), len(set.List()); got != want {
		t.Errorf("the section carries %d permissions, the Set declares %d", got, want)
	}
	known := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		known[k] = true
	}
	for _, entry := range doc.Services[0].Permissions {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(entry, &keys); err != nil {
			t.Fatalf("a permission entry is not an object: %s", entry)
		}
		for _, k := range required {
			if _, ok := keys[k]; !ok {
				t.Errorf("a permission entry is missing %q: %s", k, entry)
			}
		}
		for k := range keys {
			if !known[k] {
				t.Errorf("a permission entry carries %q, which the register refuses: %s", k, entry)
			}
		}
	}
}
