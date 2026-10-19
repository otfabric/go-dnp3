//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// fixture is the dnp3-interop fixture format 1.0: the simulated outstation
// and its points. The test reads it from the image it runs against, so the
// expectations cannot drift from what the reference serves.
type fixture struct {
	Outstation struct {
		Address            uint16 `json:"address"`
		MasterAddress      uint16 `json:"masterAddress"`
		Unsolicited        bool   `json:"unsolicited"`
		NeedTime           bool   `json:"needTime"`
		ColdRestartDelayMs *int   `json:"coldRestartDelayMs"`
		WarmRestartDelayMs *int   `json:"warmRestartDelayMs"`
	} `json:"outstation"`
	BinaryInputs    []fixturePoint `json:"binaryInputs"`
	DoubleBitInputs []fixturePoint `json:"doubleBitInputs"`
	BinaryOutputs   []fixturePoint `json:"binaryOutputs"`
	Counters        []fixturePoint `json:"counters"`
	FrozenCounters  []fixturePoint `json:"frozenCounters"`
	AnalogInputs    []fixturePoint `json:"analogInputs"`
	AnalogOutputs   []fixturePoint `json:"analogOutputs"`
	OctetStrings    []fixturePoint `json:"octetStrings"`
}

type fixturePoint struct {
	Index           uint32          `json:"index"`
	Value           json.RawMessage `json:"value"`
	Flags           *[]string       `json:"flags"`
	Class           uint8           `json:"class"`
	StaticVariation uint8           `json:"staticVariation"`
	EventVariation  uint8           `json:"eventVariation"`
	Target          *uint32         `json:"target"`
	SelectRequired  bool            `json:"selectRequired"`
	Min             *float64        `json:"min"`
	Max             *float64        `json:"max"`
}

func parseFixture(b []byte) (*fixture, error) {
	f := &fixture{}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, err
	}
	return f, nil
}

var flagBits = map[string]app.Flags{
	"ONLINE": app.FlagOnline, "RESTART": app.FlagRestart, "COMM_LOST": app.FlagCommLost,
	"REMOTE_FORCED": app.FlagRemoteForced, "LOCAL_FORCED": app.FlagLocalForced,
	"CHATTER_FILTER": app.FlagChatterFilter, "ROLLOVER": app.FlagRollover, "DISCONTINUITY": app.FlagDiscontinuity,
	"OVER_RANGE": app.FlagOverRange, "REFERENCE_ERR": app.FlagReferenceErr,
}

// flags returns the point's flags: ONLINE when the fixture names none.
func (p fixturePoint) flags() app.Flags {
	if p.Flags == nil {
		return app.FlagOnline
	}
	var f app.Flags
	for _, n := range *p.Flags {
		f |= flagBits[n]
	}
	return f
}

func (p fixturePoint) number() float64 {
	var v float64
	_ = json.Unmarshal(p.Value, &v)
	return v
}

func (p fixturePoint) boolean() bool {
	var v bool
	_ = json.Unmarshal(p.Value, &v)
	return v
}

func (p fixturePoint) octets() []byte {
	var s string
	_ = json.Unmarshal(p.Value, &s)
	b, _ := hex.DecodeString(s)
	return b
}

// The fixture's defaults when a point names no variation (FIXTURES.md).
const defaultVariation = 0

func (p fixturePoint) config(staticDefault, eventDefault uint8) server.PointConfig {
	c := server.PointConfig{Class: server.Class(p.Class), StaticVariation: p.StaticVariation, EventVariation: p.EventVariation}
	if c.StaticVariation == defaultVariation {
		c.StaticVariation = staticDefault
	}
	if c.EventVariation == defaultVariation {
		c.EventVariation = eventDefault
	}
	return c
}

// station is go-dnp3's outstation serving a fixture, with the control
// semantics of FIXTURES.md: targets, select-required outputs, ranges.
type station struct {
	f   *fixture
	srv *server.Server

	mu      sync.Mutex
	times   []time.Time
	restart []bool
}

func newStation(f *fixture, opts ...server.Option) (*station, error) {
	st := &station{f: f}
	o := []server.Option{
		server.WithAddress(link.Address(f.Outstation.Address)),
		server.WithMasters(link.Address(f.Outstation.MasterAddress)),
		server.WithHandler(st),
	}
	if f.Outstation.Unsolicited {
		o = append(o, server.WithUnsolicited(server.Unsolicited{Enabled: true}))
	}
	if f.Outstation.NeedTime {
		o = append(o, server.WithTimeSync(24*time.Hour))
	}
	srv, err := server.New(append(o, opts...)...)
	if err != nil {
		return nil, err
	}
	st.srv = srv
	db := srv.Database()
	add := func(t server.PointType, p fixturePoint, sd, ed uint8, v app.Value) error {
		if err := db.Add(t, p.Index, p.config(sd, ed), v); err != nil {
			return fmt.Errorf("%s %d: %w", t, p.Index, err)
		}
		return nil
	}
	for _, p := range f.BinaryInputs {
		if err := add(server.BinaryInput, p, 2, 2, app.Binary{Value: p.boolean(), Flags: p.flags()}); err != nil {
			return nil, err
		}
	}
	for _, p := range f.DoubleBitInputs {
		if err := add(server.DoubleBitInput, p, 2, 2, app.DoubleBitBinary{Value: app.DoubleBit(p.number()), Flags: p.flags()}); err != nil {
			return nil, err
		}
	}
	for _, p := range f.BinaryOutputs {
		if err := add(server.BinaryOutput, p, 2, 2, app.Binary{Value: p.boolean(), Flags: p.flags()}); err != nil {
			return nil, err
		}
	}
	for _, p := range f.Counters {
		if err := add(server.Counter, p, 1, 1, app.Counter{Value: uint32(p.number()), Flags: p.flags()}); err != nil {
			return nil, err
		}
	}
	for _, p := range f.FrozenCounters {
		if err := add(server.FrozenCounter, p, 1, 1, app.Counter{Value: uint32(p.number()), Flags: p.flags()}); err != nil {
			return nil, err
		}
	}
	for _, p := range f.AnalogInputs {
		if err := add(server.AnalogInput, p, 1, 1, app.Analog{Value: p.number(), Flags: p.flags()}); err != nil {
			return nil, err
		}
	}
	for _, p := range f.AnalogOutputs {
		if err := add(server.AnalogOutput, p, 1, 1, app.Analog{Value: p.number(), Flags: p.flags()}); err != nil {
			return nil, err
		}
	}
	for _, p := range f.OctetStrings {
		if err := add(server.OctetString, p, 0, 0, app.OctetString{Data: p.octets()}); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func (st *station) output(c server.Command) (fixturePoint, server.PointType, bool) {
	list, t := st.f.BinaryOutputs, server.BinaryOutput
	if c.GV.Group() == 41 {
		list, t = st.f.AnalogOutputs, server.AnalogOutput
	}
	for _, p := range list {
		if p.Index == c.Index {
			return p, t, true
		}
	}
	return fixturePoint{}, t, false
}

// check applies the control table of FIXTURES.md up to the effect.
func (st *station) check(c server.Command, direct bool) app.CommandStatus {
	p, _, ok := st.output(c)
	if !ok {
		return app.StatusNotSupported
	}
	switch v := c.Value.(type) {
	case app.CROB:
		if _, ok := crobValue(v); !ok {
			return app.StatusNotSupported
		}
	case app.AnalogOutput:
		if (p.Min != nil && v.Value < *p.Min) || (p.Max != nil && v.Value > *p.Max) {
			return app.StatusOutOfRange
		}
	}
	if direct && p.SelectRequired {
		return app.StatusNotSupported
	}
	return app.StatusSuccess
}

// crobValue maps the supported control codes to the output value.
func crobValue(c app.CROB) (bool, bool) {
	switch {
	case c.Op == app.OpLatchOn && c.TripClose == app.TCCNul, c.Op == app.OpPulseOn && c.TripClose == app.TCCClose:
		return true, true
	case c.Op == app.OpLatchOff && c.TripClose == app.TCCNul, c.Op == app.OpPulseOn && c.TripClose == app.TCCTrip:
		return false, true
	default:
		return false, false
	}
}

func (st *station) Select(_ context.Context, c server.Command) app.CommandStatus {
	return st.check(c, false)
}

func (st *station) Operate(_ context.Context, c server.Command, op server.OperateType) app.CommandStatus {
	if s := st.check(c, op != server.SelectBeforeOperate); s != app.StatusSuccess {
		return s
	}
	p, t, _ := st.output(c)
	db := st.srv.Database()
	_ = db.Batch(func(b *server.Batch) error {
		switch v := c.Value.(type) {
		case app.CROB:
			on, _ := crobValue(v)
			_ = b.Update(t, c.Index, app.Binary{Value: on, Flags: p.flags()}, server.EventOnChange)
			if p.Target != nil {
				_ = b.Update(server.BinaryInput, *p.Target, app.Binary{Value: on, Flags: st.flagsOf(st.f.BinaryInputs, *p.Target)}, server.EventOnChange)
			}
		case app.AnalogOutput:
			_ = b.Update(t, c.Index, app.Analog{Value: v.Value, Flags: p.flags()}, server.EventOnChange)
			if p.Target != nil {
				_ = b.Update(server.AnalogInput, *p.Target, app.Analog{Value: v.Value, Flags: st.flagsOf(st.f.AnalogInputs, *p.Target)}, server.EventOnChange)
			}
		}
		return nil
	})
	return app.StatusSuccess
}

func (st *station) flagsOf(ps []fixturePoint, index uint32) app.Flags {
	for _, p := range ps {
		if p.Index == index {
			return p.flags()
		}
	}
	return app.FlagOnline
}

func (st *station) Restart(_ context.Context, cold bool) (time.Duration, error) {
	d := st.f.Outstation.WarmRestartDelayMs
	if cold {
		d = st.f.Outstation.ColdRestartDelayMs
	}
	if d == nil {
		return 0, fmt.Errorf("restart not configured")
	}
	st.mu.Lock()
	st.restart = append(st.restart, cold)
	st.mu.Unlock()
	return time.Duration(*d) * time.Millisecond, nil
}

func (st *station) SetTime(_ context.Context, t time.Time) {
	st.mu.Lock()
	st.times = append(st.times, t)
	st.mu.Unlock()
}

// expectedStatic returns the objects the fixture says class 0 holds, keyed
// by group, variation and index, as the contract prints them.
func (f *fixture) expectedStatic() map[string]any {
	out := map[string]any{}
	put := func(g uint8, def uint8, ps []fixturePoint, value func(fixturePoint) any) {
		for _, p := range ps {
			v := p.StaticVariation
			if v == 0 {
				v = def
			}
			if g == 110 {
				v = uint8(len(p.octets()))
			}
			out[fmt.Sprintf("g%dv%d/%d", g, v, p.Index)] = value(p)
		}
	}
	put(1, 2, f.BinaryInputs, func(p fixturePoint) any { return p.boolean() })
	put(3, 2, f.DoubleBitInputs, func(p fixturePoint) any { return p.number() })
	put(10, 2, f.BinaryOutputs, func(p fixturePoint) any { return p.boolean() })
	put(20, 1, f.Counters, func(p fixturePoint) any { return p.number() })
	put(21, 1, f.FrozenCounters, func(p fixturePoint) any { return p.number() })
	put(30, 1, f.AnalogInputs, func(p fixturePoint) any { return p.number() })
	put(40, 1, f.AnalogOutputs, func(p fixturePoint) any { return p.number() })
	put(110, 0, f.OctetStrings, func(p fixturePoint) any { return hex.EncodeToString(p.octets()) })
	return out
}
