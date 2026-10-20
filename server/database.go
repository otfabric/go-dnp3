// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"math"
	"slices"
	"sync"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// PointType is a kind of point in the [Database].
type PointType uint8

// Point types.
const (
	BinaryInput PointType = iota
	DoubleBitInput
	BinaryOutput
	Counter
	FrozenCounter
	AnalogInput
	FrozenAnalogInput
	AnalogOutput
	OctetString
	// SecurityStatistic are the Secure Authentication statistics (group
	// 121, events group 122). The outstation keeps them per association
	// when secure authentication is on; they cannot be added to the
	// database.
	SecurityStatistic
	// BinaryOutputCommand and AnalogOutputCommand are the command events
	// (groups 13 and 43) of the outputs whose PointConfig has a
	// CommandEventClass. They have no static objects and cannot be added
	// to the database.
	BinaryOutputCommand
	AnalogOutputCommand
	// TimeAndInterval are indexed absolute times with an interval (g50v4,
	// app.AbsoluteTime with Units), for example a schedule. They have no
	// events and no class.
	TimeAndInterval
	numPointTypes
)

// String returns the name of the point type, for example "analog input".
func (t PointType) String() string {
	switch t {
	case BinaryInput:
		return "binary input"
	case DoubleBitInput:
		return "double-bit input"
	case BinaryOutput:
		return "binary output"
	case Counter:
		return "counter"
	case FrozenCounter:
		return "frozen counter"
	case AnalogInput:
		return "analog input"
	case FrozenAnalogInput:
		return "frozen analog input"
	case AnalogOutput:
		return "analog output"
	case OctetString:
		return "octet string"
	case SecurityStatistic:
		return "security statistic"
	case BinaryOutputCommand:
		return "binary output command"
	case AnalogOutputCommand:
		return "analog output command"
	case TimeAndInterval:
		return "time and interval"
	default:
		return fmt.Sprintf("point type %d", uint8(t))
	}
}

// typeInfo is what the outstation knows about a point type: its groups and
// default variations.
type typeInfo struct {
	staticGroup, eventGroup uint8
	staticDefault           uint8
	eventDefault            uint8
}

var types = [numPointTypes]typeInfo{
	BinaryInput:         {1, 2, 2, 2},
	DoubleBitInput:      {3, 4, 2, 2},
	BinaryOutput:        {10, 11, 2, 2},
	Counter:             {20, 22, 1, 5},
	FrozenCounter:       {21, 23, 1, 5},
	AnalogInput:         {30, 32, 1, 3},
	FrozenAnalogInput:   {31, 33, 1, 3},
	AnalogOutput:        {40, 42, 1, 3},
	OctetString:         {110, 111, 0, 0},
	SecurityStatistic:   {121, 122, 1, 2},
	BinaryOutputCommand: {0, 13, 0, 2},
	AnalogOutputCommand: {0, 43, 0, 3},
	TimeAndInterval:     {50, 0, 4, 0},
}

// pointTypeOfGroup returns the point type whose static or event group is g.
func pointTypeOfGroup(g uint8) (PointType, bool, bool) {
	for t := range numPointTypes {
		switch g {
		case 0:
			// Group 0 is device attributes; no type has static group 0
			// objects.
		case types[t].staticGroup:
			return t, false, true
		case types[t].eventGroup:
			return t, true, true
		}
	}
	return 0, false, false
}

// Class is an event class: 0 means the point produces no events (it is
// still reported in class 0), 1..3 are the event classes.
type Class uint8

// PointConfig configures one point.
type PointConfig struct {
	// Class is the event class, 0..3. Events are only produced for 1..3.
	Class Class

	// StaticVariation is the variation of the point in class 0 and in
	// reads of "any variation"; 0 selects the type's default (g1v2, g3v2,
	// g10v2, g20v1, g21v1, g30v1, g31v1, g40v1).
	StaticVariation uint8

	// EventVariation is the variation of the point's events; 0 selects
	// the default (g2v2, g4v2, g11v2, g22v5, g23v5, g32v3, g33v3, g42v3).
	EventVariation uint8

	// Deadband applies to counters, frozen counters and analog points: a
	// change of the value produces an event only when it exceeds the
	// deadband. Flag changes always produce one.
	Deadband float64

	// ExcludeFromClass0 leaves the point out of class 0 responses; it can
	// still be read by group and variation.
	ExcludeFromClass0 bool

	// CommandEventClass, for binary and analog outputs, reports every
	// OPERATE, DIRECT_OPERATE and DIRECT_OPERATE_NR of the point as a
	// command event in that class: g13 (the commanded state) or g43 (the
	// commanded value) with the status the handler returned. 0 reports
	// none.
	CommandEventClass Class

	// CommandEventVariation is the variation of the command events; 0
	// selects g13v2 or g43v3 (with time).
	CommandEventVariation uint8
}

type point struct {
	index uint32
	cfg   PointConfig
	value app.Value
	// last is the value of the last event, for change detection.
	last app.Value
}

// Database holds the points of an outstation. It is safe for concurrent
// use; updates produce events in the event buffers of every association.
type Database struct {
	srv *Server

	mu     sync.RWMutex
	points [numPointTypes]map[uint32]*point
	// sorted holds the indexes of each type in ascending order; nil when
	// it must be rebuilt.
	sorted [numPointTypes][]uint32
}

func newDatabase(s *Server) *Database {
	db := &Database{srv: s}
	for t := range db.points {
		db.points[t] = make(map[uint32]*point)
	}
	return db
}

// valueKind checks that v is the value type of t.
func valueKind(t PointType, v app.Value) error {
	ok := false
	switch t {
	case BinaryInput, BinaryOutput:
		_, ok = v.(app.Binary)
	case DoubleBitInput:
		_, ok = v.(app.DoubleBitBinary)
	case Counter, FrozenCounter:
		_, ok = v.(app.Counter)
	case AnalogInput, FrozenAnalogInput, AnalogOutput:
		_, ok = v.(app.Analog)
	case TimeAndInterval:
		_, ok = v.(app.AbsoluteTime)
	case OctetString:
		var s app.OctetString
		s, ok = v.(app.OctetString)
		if ok && (len(s.Data) == 0 || len(s.Data) > 255) {
			return fmt.Errorf("%w: octet string of %d octets", dnp3.ErrInvalidOption, len(s.Data))
		}
	default:
	}
	if !ok {
		return fmt.Errorf("%w: %T is not a %s value", dnp3.ErrInvalidOption, v, t)
	}
	return nil
}

// Add adds a point with its configuration and initial value. Adding an
// index that exists replaces its configuration and value.
func (db *Database) Add(t PointType, index uint32, cfg PointConfig, initial app.Value) error {
	if t >= numPointTypes || t == SecurityStatistic || t == BinaryOutputCommand || t == AnalogOutputCommand {
		return fmt.Errorf("%w: %s", dnp3.ErrInvalidOption, t)
	}
	if err := valueKind(t, initial); err != nil {
		return err
	}
	if cfg.Class > 3 {
		return fmt.Errorf("%w: class %d", dnp3.ErrInvalidOption, cfg.Class)
	}
	if err := checkVariation(t, cfg); err != nil {
		return err
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	_, existed := db.points[t][index]
	db.points[t][index] = &point{index: index, cfg: cfg, value: initial, last: initial}
	if !existed {
		db.rebuildSorted(t)
	}
	return nil
}

func checkVariation(t PointType, cfg PointConfig) error {
	ti := types[t]
	if t == OctetString {
		return nil
	}
	if t == TimeAndInterval {
		if cfg.Class != 0 || cfg.EventVariation != 0 || (cfg.StaticVariation != 0 && cfg.StaticVariation != 4) {
			return fmt.Errorf("%w: a time and interval is g50v4 and has no events", dnp3.ErrInvalidOption)
		}
		return nil
	}
	if v := cfg.StaticVariation; v != 0 && !app.GV(ti.staticGroup, v).Known() {
		return fmt.Errorf("%w: static variation g%dv%d", dnp3.ErrInvalidOption, ti.staticGroup, v)
	}
	if v := cfg.EventVariation; v != 0 && !app.GV(ti.eventGroup, v).Known() {
		return fmt.Errorf("%w: event variation g%dv%d", dnp3.ErrInvalidOption, ti.eventGroup, v)
	}
	if cfg.CommandEventClass > 3 {
		return fmt.Errorf("%w: command event class %d", dnp3.ErrInvalidOption, cfg.CommandEventClass)
	}
	if cfg.CommandEventClass != 0 || cfg.CommandEventVariation != 0 {
		ct := BinaryOutputCommand
		switch t {
		case BinaryOutput:
		case AnalogOutput:
			ct = AnalogOutputCommand
		default:
			return fmt.Errorf("%w: command events for a %s", dnp3.ErrInvalidOption, t)
		}
		if v := cfg.CommandEventVariation; v != 0 && !app.GV(types[ct].eventGroup, v).Known() {
			return fmt.Errorf("%w: command event variation g%dv%d", dnp3.ErrInvalidOption, types[ct].eventGroup, v)
		}
	}
	return nil
}

// Remove removes a point. It reports whether the point existed.
func (db *Database) Remove(t PointType, index uint32) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	if t >= numPointTypes {
		return false
	}
	if _, ok := db.points[t][index]; !ok {
		return false
	}
	delete(db.points[t], index)
	db.rebuildSorted(t)
	return true
}

// Get returns the current value of a point.
func (db *Database) Get(t PointType, index uint32) (app.Value, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if t >= numPointTypes {
		return nil, false
	}
	p, ok := db.points[t][index]
	if !ok {
		return nil, false
	}
	return p.value, true
}

// Len returns the number of points of type t.
func (db *Database) Len(t PointType) int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if t >= numPointTypes {
		return 0
	}
	return len(db.points[t])
}

// EventMode selects when an update produces an event.
type EventMode uint8

// Event modes.
const (
	// EventOnChange produces an event when the value changes (beyond the
	// deadband) or the flags change. It is the default.
	EventOnChange EventMode = iota
	// EventForce always produces an event, also for an unchanged value.
	EventForce
	// EventSuppress never produces one: the static value changes
	// silently.
	EventSuppress
)

// Update sets the value of a point and produces an event as mode says. A
// zero Time in the value is stamped with the outstation's clock for the
// event.
func (db *Database) Update(t PointType, index uint32, v app.Value, mode EventMode) error {
	return db.Batch(func(b *Batch) error { return b.Update(t, index, v, mode) })
}

// Batch is a set of updates applied together: the events they produce
// reach the event buffers at once, so that they are reported in the same
// response.
type Batch struct {
	db     *Database
	events []event
}

// Update is [Database.Update] inside a batch.
func (b *Batch) Update(t PointType, index uint32, v app.Value, mode EventMode) error {
	if t >= numPointTypes || t == SecurityStatistic || t == BinaryOutputCommand || t == AnalogOutputCommand {
		return fmt.Errorf("%w: %s", dnp3.ErrInvalidOption, t)
	}
	if err := valueKind(t, v); err != nil {
		return err
	}
	p, ok := b.db.points[t][index]
	if !ok {
		return fmt.Errorf("%w: no %s at index %d", dnp3.ErrInvalidOption, t, index)
	}
	p.value = v
	if p.cfg.Class == 0 || mode == EventSuppress {
		return nil
	}
	if mode == EventForce || changed(p.last, v, p.cfg.Deadband) {
		p.last = v
		b.events = append(b.events, b.db.newEvent(t, p, v))
	}
	return nil
}

// Batch runs fn with the database locked and then hands the events it
// produced to every association. When fn returns an error the updates
// made so far are kept but no events are reported for them.
func (db *Database) Batch(fn func(*Batch) error) error {
	db.mu.Lock()
	b := &Batch{db: db}
	err := fn(b)
	db.mu.Unlock()
	if err == nil && len(b.events) > 0 && db.srv != nil {
		db.srv.publish(b.events)
	}
	return err
}

func (db *Database) newEvent(t PointType, p *point, v app.Value) event {
	ts := timeOf(v)
	if ts == 0 && db.srv != nil {
		ts = db.srv.clock.now()
		v = withTime(v, ts)
	}
	return event{typ: t, index: p.index, class: p.cfg.Class, variation: p.cfg.EventVariation, value: v}
}

func timeOf(v app.Value) app.Timestamp {
	switch x := v.(type) {
	case app.Binary:
		return x.Time
	case app.DoubleBitBinary:
		return x.Time
	case app.Counter:
		return x.Time
	case app.Analog:
		return x.Time
	default:
		return 0
	}
}

func withTime(v app.Value, ts app.Timestamp) app.Value {
	switch x := v.(type) {
	case app.Binary:
		x.Time = ts
		return x
	case app.DoubleBitBinary:
		x.Time = ts
		return x
	case app.Counter:
		x.Time = ts
		return x
	case app.Analog:
		x.Time = ts
		return x
	default:
		return v
	}
}

// changed reports whether v differs from the value of the last event
// enough to produce a new one.
func changed(last, v app.Value, deadband float64) bool {
	switch x := v.(type) {
	case app.Binary:
		l := last.(app.Binary)
		return l.Value != x.Value || l.Flags != x.Flags
	case app.DoubleBitBinary:
		l := last.(app.DoubleBitBinary)
		return l.Value != x.Value || l.Flags != x.Flags
	case app.Counter:
		l := last.(app.Counter)
		if l.Flags != x.Flags {
			return true
		}
		// Counters wrap: the change is the unsigned difference.
		d := min(x.Value-l.Value, l.Value-x.Value)
		return float64(d) > deadband || (deadband == 0 && d != 0)
	case app.Analog:
		l := last.(app.Analog)
		if l.Flags != x.Flags {
			return true
		}
		if math.IsNaN(x.Value) != math.IsNaN(l.Value) {
			return true
		}
		d := math.Abs(x.Value - l.Value)
		return d > deadband || (deadband == 0 && d != 0)
	case app.OctetString:
		l := last.(app.OctetString)
		return string(l.Data) != string(x.Data)
	default:
		return false
	}
}

// indexes returns the sorted indexes of type t. The caller holds mu (read
// or write). The slice is rebuilt by Add and Remove under the write lock,
// so reads never mutate shared state.
func (db *Database) indexes(t PointType) []uint32 {
	return db.sorted[t]
}

// rebuildSorted recomputes the sorted index slice of t. The caller holds
// the write lock.
func (db *Database) rebuildSorted(t PointType) {
	idx := make([]uint32, 0, len(db.points[t]))
	for i := range db.points[t] {
		idx = append(idx, i)
	}
	slices.Sort(idx)
	db.sorted[t] = idx
}

// assignClass sets the class of the points of t in the range (all when
// all is set). It reports whether every index of the range existed. The
// caller holds mu for writing.
func (db *Database) assignClass(t PointType, all bool, start, stop uint32, c Class) bool {
	if all {
		for _, p := range db.points[t] {
			p.cfg.Class = c
		}
		return true
	}
	ok := true
	for i := uint64(start); i <= uint64(stop); i++ {
		p, exists := db.points[t][uint32(i)]
		if !exists {
			ok = false
			continue
		}
		p.cfg.Class = c
	}
	return ok
}
