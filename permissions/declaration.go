package permissions

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Rung is one level of a service's own role ladder: a scope group and the name
// of a level in it, such as group "projects" and level "read". On a token it
// travels as the scope `<group>:<level>`. (It is called a rung here because
// [Level] is the check a route makes.)
type Rung struct {
	// Group is the scope group, one lower-case word such as "projects".
	Group string `json:"group"`
	// Level is the level's name in the group, one lower-case word such as "write".
	Level string `json:"level"`
	// Description is one sentence in English saying what the level allows. It is
	// optional and left out of the document when empty.
	Description string `json:"description,omitempty"`
}

var rungShape = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

const (
	maxRungWord        = 64
	maxRungDescription = 256
)

// AddLevels attaches levels to the Set, so that the document that declares the
// service ([Declaration], [Set.Section]) states the rungs of its role ladder
// beside its permissions. A group and a level are each one lower-case word of
// letters, digits and "-", with no ":", "/" or space; a description, when given,
// has no surrounding space. A level named twice, within the call or against ones
// already attached, is an error. A call that returns an error attaches nothing.
//
// Call it where the Set is built, when the package loads: a Set is not safe to
// change while it is being read from other goroutines.
func (s *Set) AddLevels(levels ...Rung) error {
	added := make([]Rung, 0, len(levels))
	seen := map[[2]string]bool{}
	for _, r := range s.levels {
		seen[[2]string{r.Group, r.Level}] = true
	}
	var errs []error
	for _, r := range levels {
		name := r.Group + ":" + r.Level
		switch {
		case len(r.Group) > maxRungWord || !rungShape.MatchString(r.Group):
			errs = append(errs, fmt.Errorf("permissions: level %q: the group must be one lower-case word", name))
		case len(r.Level) > maxRungWord || !rungShape.MatchString(r.Level):
			errs = append(errs, fmt.Errorf("permissions: level %q: the level must be one lower-case word", name))
		case strings.TrimSpace(r.Description) != r.Description || len(r.Description) > maxRungDescription:
			errs = append(errs, fmt.Errorf("permissions: level %q: the description must be text with no surrounding space", name))
		case seen[[2]string{r.Group, r.Level}]:
			errs = append(errs, fmt.Errorf("permissions: level %q is declared twice", name))
		default:
			seen[[2]string{r.Group, r.Level}] = true
			added = append(added, r)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.levels = append(s.levels, added...)

	return nil
}

// Levels answers the levels attached to the Set, in the order attached.
func (s *Set) Levels() []Rung {
	return slices.Clone(s.levels)
}

// Declaration renders the document that declares one or more Sets to the
// membership register: one service entry per Set, in the order given, each with
// its key, display name, its levels (left out when the Set has none) and its
// permissions (an empty list for a Set that declares none). The same Sets always
// render the same bytes. Two Sets under one service key are an error, since the
// register would take the second for a repeat of the first.
func Declaration(sets ...*Set) ([]byte, error) {
	type service struct {
		Key         string       `json:"key"`
		DisplayName string       `json:"displayName"`
		Roles       []Rung       `json:"roles,omitempty"`
		Permissions []Permission `json:"permissions"`
	}
	doc := struct {
		Services []service `json:"services"`
	}{Services: make([]service, 0, len(sets))}
	seen := map[string]bool{}
	for i, s := range sets {
		if s == nil {
			return nil, fmt.Errorf("permissions: declaration set %d is nil", i)
		}
		if seen[s.service] {
			return nil, fmt.Errorf("permissions: service %s is in the declaration twice", s.service)
		}
		seen[s.service] = true
		doc.Services = append(doc.Services, service{
			Key: s.service, DisplayName: s.displayName, Roles: s.Levels(), Permissions: s.List(),
		})
	}
	// encoding/json writes a map's keys in sorted order, so the same lists always
	// render the same bytes.
	return json.MarshalIndent(doc, "", "  ")
}

// ServiceKeys answers the service keys a [Declaration] of the Sets carries, in
// the order given. The sender needs them to ask for a token that names exactly
// them.
func ServiceKeys(sets ...*Set) []string {
	keys := make([]string, 0, len(sets))
	for _, s := range sets {
		if s != nil {
			keys = append(keys, s.service)
		}
	}

	return keys
}
