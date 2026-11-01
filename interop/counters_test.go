//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
)

// Counters that really change (contract 1.4), both ways: go-dnp3's master on
// a reference outstation whose counter counts, and reference masters on
// go-dnp3's outstation, whose policy for a freeze of an unchanged counter is
// to raise no event. That policy is go-dnp3's: nothing here says what IEEE
// 1815 requires of it (INTEROPERABILITY.md).

const countersFixture = "/fixtures/counters/fixture.json"

// increment runs counter-increment in the reference server's container.
func (s *refServer) increment(t *testing.T, index, by int) {
	t.Helper()
	out, stderr, err := docker("exec", s.name, "dnp3-interop", "counter-increment",
		"--index", fmt.Sprint(index), "--by", fmt.Sprint(by))
	if err != nil {
		t.Fatalf("counter-increment: %v\n%s%s", err, out, stderr)
	}
	var r struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || !r.OK {
		t.Fatalf("counter-increment: %v: %s", err, out)
	}
}

// events are the frozen counter events of a poll, as "g23vV:I=VALUE", sorted.
func frozenEventsOf(res *client.Result) []string {
	var out []string
	for _, m := range res.Measurements() {
		if m.GV.Group() == 23 {
			out = append(out, fmt.Sprintf("v%d:%d=%d", m.GV.Variation(), m.Index, m.Value.(app.Counter).Value))
		}
	}
	slices.Sort(out)
	return out
}

func TestClientCountersChange(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "counterIncrementServer", "frozenCounterEventsServer")
			policies := a.capabilities(t).FrozenEventPolicies
			for _, policy := range policies {
				t.Run(policy, func(t *testing.T) {
					args := []string{"--fixture", countersFixture}
					if len(policies) > 1 {
						args = append(args, "--frozen-event-policy", policy)
					}
					s := startServer(t, a, args...)
					c := dialRef(t, s)
					ctx := tctx(t)
					freeze := func() time.Time {
						t.Helper()
						before := time.Now()
						if err := c.Freeze(ctx, false, false, app.AllObjects(app.G20V0)); err != nil {
							t.Fatalf("freeze: %v", err)
						}
						return before
					}
					poll := func(want ...string) *client.Result {
						t.Helper()
						res, err := c.EventPoll(ctx, 3)
						if err != nil {
							t.Fatal(err)
						}
						if got := frozenEventsOf(res); !slices.Equal(got, want) {
							t.Fatalf("frozen counter events %v, want %v", got, want)
						}
						return res
					}
					checkTimes := func(res *client.Result, from time.Time) {
						t.Helper()
						for _, m := range res.Measurements() {
							if m.GV.Group() != 23 {
								continue
							}
							at := m.Value.(app.Counter).Time.Time()
							if at.Before(from.Add(-2*time.Second)) || at.After(time.Now().Add(2*time.Second)) {
								t.Errorf("event of %d at %v, freeze at %v", m.Index, at, from)
							}
						}
					}
					from := freeze()
					checkTimes(poll("v5:0=100", "v6:1=200"), from)

					// The same again: the policy, and a new time of freeze either way.
					from = freeze()
					if policy == "always" {
						checkTimes(poll("v5:0=100", "v6:1=200"), from)
					} else {
						poll()
					}
					res, err := c.Read(ctx, app.IndexRange(app.G21V5, 0, 1))
					if err != nil {
						t.Fatal(err)
					}
					for _, m := range res.Measurements() {
						if at := m.Value.(app.Counter).Time.Time(); at.Before(from.Add(-2 * time.Second)) {
							t.Errorf("g21v5 of %d at %v, newer freeze at %v", m.Index, at, from)
						}
					}

					// A real change.
					s.increment(t, 0, 5)
					poll()
					from = freeze()
					if policy == "always" {
						checkTimes(poll("v5:0=105", "v6:1=200"), from)
					} else {
						checkTimes(poll("v5:0=105"), from)
					}
					res, err = c.Read(ctx, app.IndexRange(app.G21V0, 0, 0), app.IndexRange(app.G20V0, 0, 0))
					if err != nil {
						t.Fatal(err)
					}
					for _, m := range res.Measurements() {
						if v := m.Value.(app.Counter).Value; v != 105 {
							t.Errorf("%s:%d = %d after the change", m.GV, m.Index, v)
						}
					}
				})
			}
		})
	}
}

// serveCounters starts go-dnp3's outstation for the counters fixture, for
// masters in containers.
func serveCounters(t *testing.T, a adapter) (*station, int) {
	t.Helper()
	st, err := newStation(a.fixtureNamed(t, "counters"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = st.srv.Serve(l) }()
	t.Cleanup(func() { _ = st.srv.Close() })
	return st, l.Addr().(*net.TCPAddr).Port
}

func objectsOf(r *result, group int) string {
	var out []string
	for _, o := range r.Objects {
		if o.Group == group {
			out = append(out, fmt.Sprintf("g%dv%d:%d=%v", o.Group, o.Variation, o.Index, o.Value))
		}
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

// TestServerFrozenEventsOnChange: go-dnp3's outstation raises a frozen counter
// event only for a frozen value that changed, as every reference master sees
// it, with the time of the freeze in g23v5, g23v6 and g21v5.
func TestServerFrozenEventsOnChange(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "frozenCounterEventTimeClient")
			st, port := serveCounters(t, a)
			freeze := func() time.Time {
				t.Helper()
				before := time.Now()
				if r := runClient(t, a, port, "freeze"); !r.OK {
					t.Fatalf("freeze: %s", r.errorCode())
				}
				return before
			}
			poll := func(want string, from time.Time) {
				t.Helper()
				r := runClient(t, a, port, "event-poll", "--classes", "3")
				if got := objectsOf(r, 23); got != want {
					t.Fatalf("frozen counter events %q, want %q", got, want)
				}
				for _, o := range r.Objects {
					at, err := time.Parse(time.RFC3339Nano, o.Time)
					if o.Group == 23 && (err != nil || at.Before(from.Add(-2*time.Second)) || at.After(time.Now().Add(2*time.Second))) {
						t.Errorf("event of %d at %q, freeze at %v", o.Index, o.Time, from)
					}
				}
			}
			poll("g23v5:0=100 g23v6:1=200", freeze())

			// Unchanged: no event, and the snapshot still moves.
			from := freeze()
			poll("", from)
			r := runClient(t, a, port, "read", "--group", "21", "--variation", "5", "--start", "0", "--stop", "1")
			if got := objectsOf(r, 21); got != "g21v5:0=100 g21v5:1=200" {
				t.Fatalf("g21v5: %q", got)
			}
			for _, o := range r.Objects {
				if at, err := time.Parse(time.RFC3339Nano, o.Time); err != nil || at.Before(from.Add(-2*time.Second)) {
					t.Errorf("g21v5 of %d at %q, newer freeze at %v", o.Index, o.Time, from)
				}
			}

			// One value changes: that event alone.
			if err := st.srv.Database().UpdateCounter(0, app.Counter{Value: 105, Flags: app.FlagOnline}); err != nil {
				t.Fatal(err)
			}
			poll("g23v5:0=105", freeze())
		})
	}
}
