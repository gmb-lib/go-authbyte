// Package permissions declares the acts a service enforces and checks them on
// its routes, from one list.
//
// A permission is one act on one feature of a service, such as removing a file
// somebody else attached to a task. On a token it travels as a scope,
// `<service>/<feature path>:<act>` — `projects/task/attachment:delete` — and a
// route checks it as an exact match on both halves, so holding one act implies no
// other, and nesting a feature under another grants nothing.
//
// A service writes its list once and builds a [Set] from it at load. The same Set
// is what it registers with the membership register ([Set.Section]) and what its
// routes check ([Set.Declared], [Gate]). A route that names an act the list does
// not declare stops the service before it serves anything, and the test kit in
// [github.com/gmb-lib/go-authbyte/permissions/permissionstest] fails a build whose
// routes and list disagree in either direction. A library that brings routes of
// its own contributes its permissions to the service's Set, under the service's
// key, and is covered by the same checks.
package permissions

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Class says whether holding a permission lets its holder change what others may
// do. The membership register uses it to decide who may hand a permission out,
// and it never changes once declared.
type Class string

const (
	// Ordinary is every act that works inside what the tenant has set up.
	Ordinary Class = "ordinary"
	// TenantConfiguration is an act that changes the tenant's own setup — the
	// lists and rules everybody else works with.
	TenantConfiguration Class = "tenantConfiguration"
	// RoleManagement is an act that changes who holds which role.
	RoleManagement Class = "roleManagement"
)

// Plane says where a permission may be granted, and it never changes once
// declared.
type Plane string

const (
	// Tenant is a permission granted to a person across the whole tenant, such as
	// registering a new project: there is no object yet to grant it on.
	Tenant Plane = "tenant"
	// Object is a permission granted on one object the service owns, such as
	// commenting on the tasks of one project.
	Object Plane = "object"
)

// Permission is one act a service enforces on one of its features.
type Permission struct {
	// Feature is the feature path: one or more lower-camel words joined by "/",
	// such as "task/attachment".
	Feature string `json:"feature"`
	// Act is one lower-camel word, such as "delete" or "deleteOwn".
	Act string `json:"act"`
	// Description is one sentence in English saying what holding the permission
	// allows. It is the label shown in any language without one of its own.
	Description string `json:"description"`
	Class       Class  `json:"class"`
	Plane       Plane  `json:"plane"`
	// Labels holds the permission's label per language tag, such as
	// {"lv": "Noņemt jebkuru failu"}.
	Labels map[string]string `json:"labels,omitempty"`
	// Retired marks a permission the service no longer hands out. It stays
	// declared, and keeps working for every role that already holds it, but it
	// cannot be given to anybody again. A permission is never removed from a list.
	Retired bool `json:"retired,omitempty"`
	// Seeds names the roles the membership register creates with every new
	// tenant that hold this permission, such as "worker" and "manager", so a
	// tenant starts with roles that work before anybody makes one. Only a
	// permission on the object plane, and never one that changes the tenant's
	// setup, is seeded. The tenant may change or delete a seeded role like any
	// other.
	Seeds []string `json:"seeds,omitempty"`
}

// Name is the permission as it travels under the given service key:
// `<service>/<feature>:<act>`.
func (p Permission) Name(service string) string {
	return service + "/" + p.Feature + ":" + p.Act
}

// Label answers the permission's label for a language tag: the tag's own label,
// then its primary language's ("pt" for "pt-BR"), then the description.
func (p Permission) Label(lang string) string {
	if l, ok := p.Labels[lang]; ok {
		return l
	}
	primary, _, _ := strings.Cut(strings.ToLower(lang), "-")
	if l, ok := p.Labels[primary]; ok {
		return l
	}

	return p.Description
}

// The shapes the membership register accepts. It refuses a declaration outside
// them and rolls the whole document back, so a list that breaks one would fail at
// a deployment's first apply instead of when the service is built.
var (
	serviceShape  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	featureShape  = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*(/[a-z][a-zA-Z0-9]*)*$`)
	actShape      = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
	languageShape = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)
)

const (
	maxService = 64
	maxFeature = 128
	maxAct     = 64
	maxLabel   = 256
)

// Set is the permissions one service declares: its own list and each
// contribution of the libraries it uses, all under the service's key.
type Set struct {
	service     string
	displayName string
	list        []Permission
	index       map[string]int
}

// New builds a service's Set from its own list and any contributions, checking
// every permission against the shapes the membership register accepts. A
// permission declared twice, in one list or across two, is an error.
func New(service, displayName string, lists ...[]Permission) (*Set, error) {
	if len(service) > maxService || !serviceShape.MatchString(service) {
		return nil, fmt.Errorf("permissions: service key %q must be lower-case letters, digits and \"-\"", service)
	}
	if strings.TrimSpace(displayName) == "" {
		return nil, fmt.Errorf("permissions: service %s has no display name", service)
	}

	s := &Set{service: service, displayName: displayName, index: map[string]int{}}
	var errs []error
	for _, list := range lists {
		for _, p := range list {
			key := p.Feature + ":" + p.Act
			if err := check(service, p); err != nil {
				errs = append(errs, err)

				continue
			}
			if _, dup := s.index[key]; dup {
				errs = append(errs, fmt.Errorf("permissions: %s is declared twice", p.Name(service)))

				continue
			}
			s.index[key] = len(s.list)
			s.list = append(s.list, clone(p))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return s, nil
}

// MustNew is New for a Set built when a package loads: a list that does not hold
// stops the service before it serves anything.
func MustNew(service, displayName string, lists ...[]Permission) *Set {
	s, err := New(service, displayName, lists...)
	if err != nil {
		panic(err)
	}

	return s
}

func check(service string, p Permission) error {
	name := p.Name(service)
	switch {
	case len(p.Feature) > maxFeature || !featureShape.MatchString(p.Feature):
		return fmt.Errorf("permissions: %s: the feature must be lower-camel words joined by \"/\"", name)
	case len(p.Act) > maxAct || !actShape.MatchString(p.Act):
		return fmt.Errorf("permissions: %s: the act must be one lower-camel word", name)
	case strings.TrimSpace(p.Description) == "" || strings.TrimSpace(p.Description) != p.Description:
		return fmt.Errorf("permissions: %s needs a description with no surrounding space", name)
	case p.Class != Ordinary && p.Class != TenantConfiguration && p.Class != RoleManagement:
		return fmt.Errorf("permissions: %s: class %q is not ordinary, tenantConfiguration or roleManagement", name, p.Class)
	case p.Plane != Tenant && p.Plane != Object:
		return fmt.Errorf("permissions: %s: plane %q is not tenant or object", name, p.Plane)
	}
	if len(p.Seeds) > 0 && (p.Plane != Object || p.Class != Ordinary) {
		return fmt.Errorf("permissions: %s: only an ordinary permission on the object plane is given to a seeded role", name)
	}
	seen := map[string]bool{}
	for _, seed := range p.Seeds {
		if len(seed) > maxAct || !actShape.MatchString(seed) {
			return fmt.Errorf("permissions: %s: seed %q must be one lower-camel word", name, seed)
		}
		if seen[seed] {
			return fmt.Errorf("permissions: %s: seed %q is named twice", name, seed)
		}
		seen[seed] = true
	}
	for lang, label := range p.Labels {
		if !languageShape.MatchString(lang) {
			return fmt.Errorf("permissions: %s: %q is not a language tag such as \"lv\"", name, lang)
		}
		if strings.TrimSpace(label) == "" || strings.TrimSpace(label) != label || len(label) > maxLabel {
			return fmt.Errorf("permissions: %s: the %s label must be text with no surrounding space", name, lang)
		}
	}

	return nil
}

func clone(p Permission) Permission {
	p.Seeds = append([]string(nil), p.Seeds...)
	if len(p.Seeds) == 0 {
		p.Seeds = nil
	}
	if p.Labels != nil {
		labels := make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			labels[k] = v
		}
		p.Labels = labels
	}

	return p
}

// Service is the key the service is registered under in the membership
// register, and the first part of every permission it declares.
func (s *Set) Service() string { return s.service }

// List answers every declared permission, in the order declared, retired ones
// included.
func (s *Set) List() []Permission {
	out := make([]Permission, len(s.list))
	for i, p := range s.list {
		out[i] = clone(p)
	}

	return out
}

// Lookup answers the declared permission for a feature and act.
func (s *Set) Lookup(feature, act string) (Permission, bool) {
	i, ok := s.index[feature+":"+act]
	if !ok {
		return Permission{}, false
	}

	return clone(s.list[i]), true
}

// Declared answers the permission a route checks, and stops the service before
// it serves anything when the Set does not declare it: a check nobody can be
// given the permission for is a route nobody can reach. Call it where the
// service's checks are built, when the package loads or the routes register.
func (s *Set) Declared(feature, act string) Perm {
	if _, ok := s.index[feature+":"+act]; !ok {
		panic("permissions: " + s.service + "/" + feature + ":" + act + " is checked but not declared")
	}

	return Perm{service: s.service, feature: feature, act: act}
}

// HeldAny reports whether the caller holds any permission this service declares,
// a retired one included.
func (s *Set) HeldAny(u Scopes) bool {
	for _, p := range s.list {
		if u.HasScopeLevel(s.service+"/"+p.Feature, p.Act) {
			return true
		}
	}

	return false
}

// Section renders the Set as the membership register's configuration section:
// the service under its key, carrying its permissions and nothing else.
// Applying it is additive and idempotent, and it is how a deployment registers
// the service's permissions — the service itself makes no call to do so.
func (s *Set) Section() ([]byte, error) {
	type service struct {
		Key         string       `json:"key"`
		DisplayName string       `json:"displayName"`
		Permissions []Permission `json:"permissions"`
	}
	// encoding/json writes a map's keys in sorted order, so the same list always
	// renders the same bytes.
	return json.MarshalIndent(struct {
		Services []service `json:"services"`
	}{Services: []service{{Key: s.service, DisplayName: s.displayName, Permissions: s.List()}}}, "", "  ")
}

// Perm is one declared permission as a route checks it. The only way to get one
// is [Set.Declared], so every Perm names a permission its Set declares.
type Perm struct {
	service string
	feature string
	act     string
}

// Feature is the permission's feature path.
func (p Perm) Feature() string { return p.feature }

// Act is the permission's act.
func (p Perm) Act() string { return p.act }

// String is the permission as it travels: `<service>/<feature>:<act>`.
func (p Perm) String() string { return p.service + "/" + p.feature + ":" + p.act }

// HeldBy reports whether the caller's token carries the permission: an exact
// match on its feature path and act, so holding one act implies no other.
func (p Perm) HeldBy(u Scopes) bool {
	return u.HasScopeLevel(p.service+"/"+p.feature, p.act)
}

// Scopes is what a check reads from the caller: whether their token carries a
// scope, as an exact match on its group and level. The authenticated user of an
// azugo request satisfies it.
type Scopes interface {
	HasScopeLevel(group, level string) bool
}
