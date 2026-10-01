// Package chart keeps a service's copy of who is below whom in a tenant's chart
// of authority, for a service that lets a position see what the people below it
// see.
//
// A tenant draws its own tree of positions and puts its people in them. A service
// that lets a person see more because of where they sit — the projects of
// everyone who reports to them — must not ask the membership register on every
// request. So it keeps a copy of the tree as a list: for each person, everyone
// below them, all the way down. A read checks the copy: a local read.
//
// This package keeps that copy current and honest, the way package placement
// keeps a copy of the roles:
//
//   - it asks the membership register for the tenant's chart every few seconds,
//     sending the version it holds, so that while nothing changed the answer is a
//     304 with no body ([Keeper.Run]);
//   - a changed answer replaces the copy, in one step the service's [Store] makes
//     atomic;
//   - a copy is trusted for one window after it was last confirmed and no longer:
//     a move in the chart is seen within one interval, and a copy older than the
//     window lifts nothing, so a person who was taken out of a position stops
//     seeing through it even if the register cannot be reached ([Keeper.Ready]
//     reports it).
//
// The register is reached through a [Source]; [NewRegister] is the one that calls
// it over the network with the service's own credential. The copy lives wherever
// the service keeps its data, behind a [Store]. A tenant without a chart, or
// whose chart is not included, is answered as an empty one.
package chart

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gmb-lib/go-authbyte/placement"
)

// Defaults for [Config], the same as the roles' copy so that one reader sees both
// change together.
const (
	// DefaultInterval is how often the register is asked.
	DefaultInterval = placement.DefaultInterval
	// DefaultTrustWindow is how long a confirmed copy is trusted.
	DefaultTrustWindow = placement.DefaultTrustWindow
)

// Config shapes a [Keeper]. Zero values take the defaults.
type Config = placement.Config

// Chart is a tenant's chart as a service copies it: for each person, the people
// below them, all the way down, each spelled as a subject key. A person with
// nobody below them has no entry, and nobody is below themselves.
type Chart struct {
	// Version is what the register answered the chart at.
	Version string
	// Below maps a subject to every subject below them.
	Below map[string][]string
}

// Source is the membership register as the copy sees it.
type Source interface {
	// Chart answers the tenant's chart. Given the version the caller holds, it
	// answers changed=false while that version is still current.
	Chart(ctx context.Context, tenant, version string) (c Chart, changed bool, err error)
}

// Store is where the service keeps its copy.
type Store interface {
	// Tenants answers every tenant the service holds a copy for.
	Tenants(ctx context.Context) ([]string, error)
	// Version answers the version of the tenant's copy, empty when it has none.
	Version(ctx context.Context, tenant string) (string, error)
	// Replace makes c the tenant's copy, confirmed at the time given. It must be
	// one transaction: a read must never see half of the old chart and half of
	// the new.
	Replace(ctx context.Context, tenant string, c Chart, at time.Time) error
	// Confirm records that the tenant's copy was found current at the time given.
	Confirm(ctx context.Context, tenant string, at time.Time) error
}

// Keeper keeps every tenant's copy current. It is safe for concurrent use.
type Keeper struct {
	src Source
	st  Store
	cfg Config

	wake chan string

	mu        sync.Mutex
	started   bool                 // the first cycle has run
	confirmed map[string]time.Time // last confirmation per tenant, this process
	extra     map[string]bool      // tenants woken that the store does not list yet
}

// New answers a Keeper over the register and the service's store.
func New(src Source, st Store, cfg Config) (*Keeper, error) {
	if src == nil || st == nil {
		return nil, errors.New("chart: a source and a store are required")
	}
	if cfg.Interval < 0 || cfg.TrustWindow < 0 {
		return nil, errors.New("chart: the interval and the trust window cannot be negative")
	}
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.TrustWindow == 0 {
		cfg.TrustWindow = DefaultTrustWindow
	}
	if cfg.TrustWindow <= cfg.Interval {
		return nil, fmt.Errorf("chart: a trust window of %s must be longer than the interval of %s, "+
			"or a single slow answer would stop every position seeing through the chart", cfg.TrustWindow, cfg.Interval)
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
		extra:     map[string]bool{},
	}, nil
}

// TrustedSince answers the moment before which a confirmed copy lifts nothing:
// the chart is read only while its tenant's copy was confirmed at or after it.
// The service passes it to wherever it reads the copy.
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
		k.fail("", fmt.Errorf("chart: list the tenants: %w", err))

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

// Sync makes one tenant's copy current. A failure to reach the register keeps the
// copy as it was.
func (k *Keeper) Sync(ctx context.Context, tenant string) error {
	version, err := k.st.Version(ctx, tenant)
	if err != nil {
		return fmt.Errorf("chart: read the copy's version: %w", err)
	}

	c, changed, err := k.src.Chart(ctx, tenant, version)
	if err != nil {
		return fmt.Errorf("chart: read the tenant's chart: %w", err)
	}

	at := k.cfg.Now()
	if changed {
		err = k.st.Replace(ctx, tenant, c, at)
	} else {
		err = k.st.Confirm(ctx, tenant, at)
	}
	if err != nil {
		return fmt.Errorf("chart: keep the copy: %w", err)
	}

	k.mu.Lock()
	k.confirmed[tenant] = at
	k.mu.Unlock()

	return nil
}

// Ready answers nil once the first cycle has run and while every tenant this
// process has seen holds a copy confirmed inside the trust window, and names
// those that do not. A service reports it on its readiness check: the chart lifts
// nothing there until the register is reached again.
func (k *Keeper) Ready() error {
	since := k.TrustedSince()

	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.started {
		return errors.New("chart: the tenants' charts have not been read yet")
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

	return fmt.Errorf("chart: the charts of %d tenant(s) are not confirmed: %s",
		len(stale), strings.Join(stale, ", "))
}
