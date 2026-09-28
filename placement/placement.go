// Package placement keeps a service's copy of a tenant's roles, for a service
// that places those roles on objects of its own.
//
// A service that owns objects — a project, a register — can let a tenant put a
// person on one of them with one of the tenant's roles. What the person may then
// do there is what the role carries in that service, and checking it on every
// request must not mean asking the membership register on every request. So the
// service keeps a copy of what each role carries, beside its placements, and
// checks a person against the copy: a local read.
//
// This package keeps that copy current and honest:
//
//   - it asks the membership register for the tenant's roles every few seconds,
//     sending the version it holds, so that while nothing changed the answer is a
//     304 with no body ([Keeper.Run]);
//   - a changed answer replaces the copy and the keys beside every placement of a
//     changed role, in one step the service's [Store] makes atomic;
//   - a copy is trusted for one window after it was last confirmed and no longer:
//     placed keys confirmed before [Keeper.TrustedSince] grant nothing, so a role
//     taken back in the register stops working here within that window even if
//     the register cannot be reached ([Keeper.Ready] reports it);
//   - after any cycle in which they changed, it reports how many times the
//     service has placed each role, so the register never deletes a role somebody
//     is still placed in.
//
// The register is reached through a [Source]; [NewRegister] is the one that
// calls it over the network with the service's own credential. The copy lives
// wherever the service keeps its data, behind a [Store].
package placement

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gmb-lib/go-authbyte/permissions"
)

// Defaults for [Config].
const (
	// DefaultInterval is how often the register is asked.
	DefaultInterval = 10 * time.Second
	// DefaultTrustWindow is how long a confirmed copy is trusted: the usual
	// lifetime of a person's access token, so that taking a role back works here
	// no later than it would through a new token.
	DefaultTrustWindow = 15 * time.Minute
)

// Role is one of a tenant's roles as a service copies it: its keys are only the
// permissions of the scope groups that service checks, each spelled as it
// travels (`<group>/<feature>:<act>`).
//
// Seed names a role the register created with the tenant, such as "manager",
// and is empty for a role the tenant made. The tenant may rename such a role or
// change what it carries; its seed never changes, so a service that must pick a
// default role — the one a new object's creator receives — picks it by seed and
// never by name.
type Role struct {
	ID          string   `json:"id"`
	Seed        string   `json:"seed,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Keys        []string `json:"keys"`
}

// Definitions is a tenant's roles and the version the register answered them at.
type Definitions struct {
	Version string
	Roles   []Role
}

// Keys is what a placement holds: the keys of its role, as last copied.
type Keys []string

// Holds reports whether the keys include the permission, as an exact match.
func (k Keys) Holds(p permissions.Perm) bool {
	return slices.Contains(k, p.String())
}

// Source is the membership register as the copy sees it.
type Source interface {
	// Definitions answers the tenant's roles. Given the version the caller
	// holds, it answers changed=false while that version is still current.
	Definitions(ctx context.Context, tenant, version string) (d Definitions, changed bool, err error)
	// Report replaces the service's count of placements per role id in the
	// tenant, a role left out counting zero. It answers the ids the register did
	// not know: a role deleted after it was placed.
	Report(ctx context.Context, tenant string, counts map[string]int) (unknown []string, err error)
}

// Store is where the service keeps its copy, beside its placements.
type Store interface {
	// Tenants answers every tenant the service holds a copy or a placement for.
	Tenants(ctx context.Context) ([]string, error)
	// Version answers the version of the tenant's copy, empty when it has none.
	Version(ctx context.Context, tenant string) (string, error)
	// Replace makes d the tenant's copy, confirmed at the time given, and
	// rewrites the keys beside every placement of a role that changed — a
	// placement of a role no longer in d keeps nothing. It must be one
	// transaction: a check must never see the new copy beside old keys.
	Replace(ctx context.Context, tenant string, d Definitions, at time.Time) error
	// Confirm records that the tenant's copy was found current at the time given.
	Confirm(ctx context.Context, tenant string, at time.Time) error
	// Counts answers the service's placements per role id in the tenant.
	Counts(ctx context.Context, tenant string) (map[string]int, error)
}

// Config shapes a [Keeper]. Zero values take the defaults.
type Config struct {
	// Interval is how often every tenant's copy is refreshed.
	Interval time.Duration
	// TrustWindow is how long after its last confirmation a copy is trusted.
	TrustWindow time.Duration
	// OnError is told about a cycle that failed for a tenant; the copy is kept
	// and the next cycle tries again. Nil discards it.
	OnError func(tenant string, err error)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Keeper keeps every tenant's copy current. It is safe for concurrent use.
type Keeper struct {
	src Source
	st  Store
	cfg Config

	wake chan string

	mu        sync.Mutex
	started   bool                      // the first cycle has run
	confirmed map[string]time.Time      // last confirmation per tenant, this process
	reported  map[string]map[string]int // last counts the register accepted, per tenant
	extra     map[string]bool           // tenants woken that the store does not list yet
}

// New answers a Keeper over the register and the service's store.
func New(src Source, st Store, cfg Config) (*Keeper, error) {
	if src == nil || st == nil {
		return nil, errors.New("placement: a source and a store are required")
	}
	if cfg.Interval < 0 || cfg.TrustWindow < 0 {
		return nil, errors.New("placement: the interval and the trust window cannot be negative")
	}
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.TrustWindow == 0 {
		cfg.TrustWindow = DefaultTrustWindow
	}
	if cfg.TrustWindow <= cfg.Interval {
		return nil, fmt.Errorf("placement: a trust window of %s must be longer than the interval of %s, "+
			"or a single slow answer would stop every placement working", cfg.TrustWindow, cfg.Interval)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Keeper{
		src:       src,
		st:        st,
		cfg:       cfg,
		wake:      make(chan string, 64),
		confirmed: map[string]time.Time{},
		reported:  map[string]map[string]int{},
		extra:     map[string]bool{},
	}, nil
}

// TrustedSince answers the moment before which a confirmed copy grants nothing:
// a placement's keys are held only while its tenant's copy was confirmed at or
// after it. The service passes it to wherever it checks a placement.
func (k *Keeper) TrustedSince() time.Time {
	return k.cfg.Now().Add(-k.cfg.TrustWindow)
}

// Wake asks for the tenant's copy now, rather than at the next cycle: a request
// arrived from a tenant this service holds no copy for yet. It never blocks.
func (k *Keeper) Wake(tenant string) {
	if tenant == "" {
		return
	}
	select {
	case k.wake <- tenant:
	default: // a full queue is already a cycle about to run
	}
}

// Run refreshes every tenant's copy once at start and then every interval, and
// any woken tenant at once, until ctx ends.
func (k *Keeper) Run(ctx context.Context) error {
	k.cycle(ctx)

	tick := time.NewTicker(k.cfg.Interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			k.cycle(ctx)
		case tenant := <-k.wake:
			k.mu.Lock()
			k.extra[tenant] = true
			k.mu.Unlock()
			k.fail(tenant, k.Sync(ctx, tenant))
		}
	}
}

// cycle refreshes every tenant the store lists and every tenant woken so far.
func (k *Keeper) cycle(ctx context.Context) {
	defer func() {
		k.mu.Lock()
		k.started = true
		k.mu.Unlock()
	}()

	tenants, err := k.st.Tenants(ctx)
	if err != nil {
		k.fail("", fmt.Errorf("placement: list the tenants: %w", err))

		return
	}

	k.mu.Lock()
	for _, t := range tenants {
		delete(k.extra, t)
	}
	for t := range k.extra {
		tenants = append(tenants, t)
	}
	k.mu.Unlock()

	for _, t := range tenants {
		if ctx.Err() != nil {
			return
		}
		k.fail(t, k.Sync(ctx, t))
	}
}

func (k *Keeper) fail(tenant string, err error) {
	if err != nil && k.cfg.OnError != nil {
		k.cfg.OnError(tenant, err)
	}
}

// Sync makes one tenant's copy current and reports its counts when they
// changed. A failure to reach the register keeps the copy as it was.
func (k *Keeper) Sync(ctx context.Context, tenant string) error {
	version, err := k.st.Version(ctx, tenant)
	if err != nil {
		return fmt.Errorf("placement: read the copy's version: %w", err)
	}

	d, changed, err := k.src.Definitions(ctx, tenant, version)
	if err != nil {
		return fmt.Errorf("placement: read the tenant's roles: %w", err)
	}

	at := k.cfg.Now()
	if changed {
		err = k.st.Replace(ctx, tenant, d, at)
	} else {
		err = k.st.Confirm(ctx, tenant, at)
	}
	if err != nil {
		return fmt.Errorf("placement: keep the copy: %w", err)
	}

	k.mu.Lock()
	k.confirmed[tenant] = at
	k.mu.Unlock()

	return k.reportCounts(ctx, tenant)
}

// reportCounts sends the tenant's counts when they differ from what the
// register last accepted, including the first time.
func (k *Keeper) reportCounts(ctx context.Context, tenant string) error {
	counts, err := k.st.Counts(ctx, tenant)
	if err != nil {
		return fmt.Errorf("placement: count the placements: %w", err)
	}
	if counts == nil {
		counts = map[string]int{}
	}

	k.mu.Lock()
	last, sent := k.reported[tenant]
	k.mu.Unlock()
	if sent && maps.Equal(last, counts) {
		return nil
	}

	unknown, err := k.src.Report(ctx, tenant, counts)
	if err != nil {
		return fmt.Errorf("placement: report the placements: %w", err)
	}

	k.mu.Lock()
	k.reported[tenant] = maps.Clone(counts)
	k.mu.Unlock()

	if len(unknown) > 0 {
		return fmt.Errorf("placement: placed roles the tenant no longer has: %s", strings.Join(unknown, ", "))
	}

	return nil
}

// Ready answers nil once the first cycle has run and while every tenant this
// process has seen holds a copy confirmed inside the trust window, and names
// those that do not. A service
// reports it on its readiness check: placements there grant nothing until the
// register is reached again.
func (k *Keeper) Ready() error {
	since := k.TrustedSince()

	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.started {
		return errors.New("placement: the tenants' roles have not been read yet")
	}

	var stale []string
	for t, at := range k.confirmed {
		if at.Before(since) {
			stale = append(stale, t)
		}
	}
	for t := range k.extra {
		if _, ok := k.confirmed[t]; !ok {
			stale = append(stale, t)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	slices.Sort(stale)

	return fmt.Errorf("placement: the roles of %d tenant(s) are not confirmed: %s",
		len(stale), strings.Join(stale, ", "))
}
