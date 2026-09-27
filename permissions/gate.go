package permissions

import (
	"strings"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
)

// Level is a coarser check a route may accept beside its permissions, such as a
// rung of a service's own role ladder. A service with no such rungs passes the
// zero Level.
type Level struct {
	// Name is how a refusal names what would have been enough, for example
	// "projects:log or projects:write".
	Name string
	// Holds reports whether the caller passes the check.
	Holds func(u Scopes) bool
}

// Levels is a Level passed by holding any one of the levels named, in one scope
// group.
func Levels(group string, levels ...string) Level {
	names := make([]string, len(levels))
	for i, l := range levels {
		names[i] = group + ":" + l
	}

	return Level{
		Name: strings.Join(names, " or "),
		Holds: func(u Scopes) bool {
			for _, l := range levels {
				if u.HasScopeLevel(group, l) {
					return true
				}
			}

			return false
		},
	}
}

// Gate guards a service's routes with its Set, and records every permission a
// route accepts, so a test can hold the routes against the list.
type Gate struct {
	set      *Set
	accepted map[Perm]bool
	deny     func(ctx *azugo.Context, requiredScope string)
}

// Gate answers a new route guard over the Set. deny is called with a sentence
// naming what the route would have accepted, before the request is answered
// 403 — the place to record the refusal as a security event. It may be nil.
func (s *Set) Gate(deny func(ctx *azugo.Context, requiredScope string)) *Gate {
	return &Gate{set: s, accepted: map[Perm]bool{}, deny: deny}
}

// OneOf passes a caller holding the level, or any one of the permissions named.
// A route whose handler then tells an act on the caller's own work from an act
// on anybody's names both permissions here and decides inside.
func (g *Gate) OneOf(level Level, h azugo.RequestHandler, accepts ...Perm) azugo.RequestHandler {
	return g.guard(level, accepts, false, h)
}

// AllOf passes a caller holding the level, or every one of the permissions
// named: for one act made of several.
func (g *Gate) AllOf(level Level, h azugo.RequestHandler, needs ...Perm) azugo.RequestHandler {
	return g.guard(level, needs, true, h)
}

// Member passes a caller holding the level or any permission this service
// declares: for the reads every member of the tenant may make, such as the
// tenant's own setup, which is the same for everybody.
func (g *Gate) Member(level Level, h azugo.RequestHandler) azugo.RequestHandler {
	required := join(level.Name, "any "+g.set.service+"/ permission")

	return func(ctx *azugo.Context) {
		if (level.Holds != nil && level.Holds(ctx.User())) || g.set.HeldAny(ctx.User()) {
			h(ctx)

			return
		}
		g.refuse(ctx, required)
	}
}

// Accepted answers every permission some route guarded by this Gate accepts.
func (g *Gate) Accepted() []Perm {
	out := make([]Perm, 0, len(g.accepted))
	for p := range g.accepted {
		out = append(out, p)
	}

	return out
}

func (g *Gate) guard(level Level, perms []Perm, all bool, h azugo.RequestHandler) azugo.RequestHandler {
	names := make([]string, len(perms))
	for i, p := range perms {
		g.accepted[p] = true
		names[i] = p.String()
	}
	required := level.Name
	switch {
	case all && len(names) > 0:
		required = join(required, "all of "+strings.Join(names, " "))
	case len(names) > 0:
		required = join(required, strings.Join(names, " or "))
	}

	return func(ctx *azugo.Context) {
		if level.Holds != nil && level.Holds(ctx.User()) {
			h(ctx)

			return
		}
		if len(perms) > 0 && holds(ctx.User(), perms, all) {
			h(ctx)

			return
		}
		g.refuse(ctx, required)
	}
}

func (g *Gate) refuse(ctx *azugo.Context, required string) {
	if g.deny != nil {
		g.deny(ctx, required)
	}
	ctx.Error(corehttp.ForbiddenError{})
}

// holds reports whether the caller holds one of the permissions, or with all
// set, every one of them.
func holds(u Scopes, perms []Perm, all bool) bool {
	for _, p := range perms {
		if p.HeldBy(u) != all {
			return !all
		}
	}

	return all
}

func join(a, b string) string {
	if a == "" {
		return b
	}

	return a + " or " + b
}
