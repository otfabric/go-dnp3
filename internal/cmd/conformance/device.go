// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"slices"
	"sync"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// The database: points of every type at indices 0..points-1, in the classes
// the dnp3c configuration (device.ini) names, which the plugin changes, and
// binary inputs 4..6 in classes 2, 2 and 3, for Assign Class (3.1r1's 8.26).
const points = 4

// maxFragment is the largest response fragment the outstation sends: small
// enough for the events of generateMultiFragmentResponse to take several
// (8.9), large enough for a class 0 response to take one.
const maxFragment = 512

// timeSync is how often the outstation asks for the time (IIN1.4), the
// Device Profile's maximum time between synchronization requests
// (timesync.maxTimeBetweenSyncRequestsMs).
const timeSync = 10 * time.Second

// assigned are the classes of the extra binary inputs.
var assigned = []server.Class{2, 2, 3}

// count is the number of points of a kind.
func count(kind string) int {
	if kind == kindBinary {
		return points + len(assigned)
	}
	return points
}

const (
	outstationAddress = 1024
	masterAddress     = 1
)

// kinds are the dnp3c point kinds, as the plugin names them.
var kinds = []string{kindBinary, kindDoubleBit, kindCounter, kindFrozenCounter, kindAnalog, kindBinaryOutput, kindAnalogOutput}

const (
	kindBinary        = "binary input"
	kindDoubleBit     = "double-bit binary input"
	kindCounter       = "counter"
	kindFrozenCounter = "frozen counter"
	kindAnalog        = "analog input"
	kindBinaryOutput  = "binary output status"
	kindAnalogOutput  = "analog output status"
)

var pointTypes = map[string]server.PointType{
	kindBinary:        server.BinaryInput,
	kindDoubleBit:     server.DoubleBitInput,
	kindCounter:       server.Counter,
	kindFrozenCounter: server.FrozenCounter,
	kindAnalog:        server.AnalogInput,
	kindBinaryOutput:  server.BinaryOutput,
	kindAnalogOutput:  server.AnalogOutput,
}

// classes of each kind's events; 0 reports none. setLevel adjusts them.
var classes = map[string]server.Class{
	kindBinary:        1,
	kindDoubleBit:     1,
	kindCounter:       3,
	kindFrozenCounter: 3,
	kindAnalog:        2,
}

// variations of each kind, static and event, within subset levels 1 and 2:
// the go-dnp3 defaults g22v5, g32v3 and g40v1 are outside them.
var variations = map[string][2]uint8{
	kindBinary:        {2, 2},
	kindDoubleBit:     {2, 2},
	kindCounter:       {1, 1},
	kindFrozenCounter: {1, 1},
	kindAnalog:        {1, 1},
	kindBinaryOutput:  {2, 0},
	kindAnalogOutput:  {2, 0},
}

// maxControls is the Device Profile's maximum number of controls in a request.
const maxControls = 2

// setLevel shapes the database to a DNP3 subset level: frozen counter
// events are level 3 objects, and double-bit inputs, which 3.1r1 has at
// level 4, are there only with doubleBit (for 2.7).
func setLevel(level int, doubleBit bool) {
	if !doubleBit {
		kinds = slices.DeleteFunc(kinds, func(k string) bool { return k == kindDoubleBit })
	}
	if level < 3 {
		classes[kindFrozenCounter] = 0
	}
}

// config is what the plugin's configuration actions change. As on a real
// device it is offline configuration: it takes effect at the next restart
// (cyclePower), which dnp3c always performs after changing it.
type config struct {
	linkConfirm  bool
	selfAddress  bool
	unsolicited  bool
	confirm      time.Duration
	unsolRetries int
	master       link.Address
	maxFragment  int
	coldRestart  bool
}

func defaultConfig() config {
	return config{
		unsolicited:  false,
		confirm:      5 * time.Second,
		unsolRetries: 5,
		master:       masterAddress,
		maxFragment:  maxFragment,
		coldRestart:  true,
	}
}

// event is one change the device made, for the checks of what was reported.
type event struct {
	kind  string
	index int
	value float64
	time  app.Timestamp // the event's time, on the outstation's clock
	wall  time.Time     // when it was generated
}

type operation struct {
	kind  string
	index int
}

type device struct {
	addr   string
	logger dnp3.Logger

	mu       sync.Mutex
	srv      *server.Server
	cfg      config // in effect
	pending  config // after the next restart
	values   map[string]map[int]app.Value
	removed  map[string]bool
	batches  [][]event
	checked  int // events of the latest batch checked by a check of its first event
	ops      []operation
	recorded map[string]map[int]float64
	timeEv   *event
	global   bool // global remote supervisory control: remote
	local    map[int]bool
	counter  float64
}

func newDevice(addr string, l *slog.Logger) *device {
	return &device{addr: addr, logger: dnp3.NewSlogLogger(l.Handler())}
}

// reset starts a procedure from a known state.
func (d *device) reset() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg = defaultConfig()
	d.pending = d.cfg
	d.values = initialValues()
	d.removed = map[string]bool{}
	d.batches = nil
	d.checked = 0
	d.ops = nil
	d.recorded = nil
	d.timeEv = nil
	d.global = true
	d.local = map[int]bool{}
	d.counter = 0
	return d.restartLocked()
}

func initialValues() map[string]map[int]app.Value {
	v := map[string]map[int]app.Value{}
	for _, k := range kinds {
		v[k] = map[int]app.Value{}
		for i := range count(k) {
			// Counters have counted, as a device's would have: 3.1r1's
			// 8.16.2.2.3 freezes them and expects nonzero frozen values.
			var x float64
			if k == kindCounter {
				x = float64(10 * (i + 1))
			}
			v[k][i] = valueOf(k, x, app.FlagOnline, 0)
		}
	}
	return v
}

// valueOf makes the go-dnp3 value of a kind of point.
func valueOf(kind string, x float64, f app.Flags, t app.Timestamp) app.Value {
	switch kind {
	case kindBinary, kindBinaryOutput:
		return app.Binary{Value: x != 0, Flags: f, Time: t}
	case kindDoubleBit:
		return app.DoubleBitBinary{Value: app.DoubleBit(x), Flags: f, Time: t}
	case kindCounter, kindFrozenCounter:
		return app.Counter{Value: uint32(x), Flags: f, Time: t}
	default:
		return app.Analog{Value: x, Flags: f, Time: t}
	}
}

// valueFlags splits a go-dnp3 value into its number and flags.
func valueFlags(v app.Value) (float64, app.Flags) {
	switch v := v.(type) {
	case app.Binary:
		if v.Value {
			return 1, v.Flags
		}
		return 0, v.Flags
	case app.DoubleBitBinary:
		return float64(v.Value), v.Flags
	case app.Counter:
		return float64(v.Value), v.Flags
	case app.Analog:
		return v.Value, v.Flags
	}
	return 0, 0
}

// restartLocked replaces the outstation with a new one, as after a power
// cycle: the pending configuration takes effect, events are lost, and the
// inputs keep their values. It returns once the new one accepts connections.
func (d *device) restartLocked() error {
	if d.srv != nil {
		_ = d.srv.Close()
		d.srv = nil
	}
	d.cfg = d.pending
	c := d.cfg
	opts := []server.Option{
		server.WithAddress(outstationAddress),
		server.WithMasters(c.master),
		server.WithHandler(&handler{d: d}),
		server.WithLogger(d.logger),
		server.WithConfirmTimeout(c.confirm),
		server.WithSelectTimeout(2 * time.Second),
		server.WithMaxControls(maxControls),
		server.WithMaxFragment(c.maxFragment, 2048),
		server.WithSelfAddress(c.selfAddress),
		server.WithTimeSync(timeSync),
		server.WithLink(server.Link{Confirmed: c.linkConfirm, Timeout: time.Second, Retries: 3, KeepAlive: -1}),
		server.WithAttributes(attributes()),
	}
	if c.unsolicited {
		opts = append(opts, server.WithUnsolicited(server.Unsolicited{Enabled: true, Retries: c.unsolRetries}))
	}
	srv, err := server.New(opts...)
	if err != nil {
		return err
	}
	db := srv.Database()
	for _, k := range kinds {
		if d.removed[k] {
			continue
		}
		for i := range count(k) {
			if err := db.Add(pointTypes[k], uint32(i), pointConfig(k, i), d.values[k][i]); err != nil {
				return err
			}
		}
	}
	var l net.Listener
	for range 50 {
		if l, err = net.Listen("tcp", d.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	go func() { _ = srv.Serve(l) }()
	d.srv = srv
	return nil
}

func attributes() map[uint8]app.Attribute {
	return map[uint8]app.Attribute{
		app.AttrManufacturerName:    app.StringAttribute("OT Fabric"),
		app.AttrProductNameAndModel: app.StringAttribute("go-dnp3 conformance outstation"),
		app.AttrSoftwareVersion:     app.StringAttribute("go-dnp3"),
		app.AttrHardwareVersion:     app.StringAttribute("none"),
		app.AttrSerialNumber:        app.StringAttribute("1"),
		app.AttrUserLocation:        app.StringAttribute("test bench"),
		app.AttrUserID:              app.StringAttribute("dut"),
		app.AttrUserDeviceName:      app.StringAttribute("dut"),
	}
}

func pointConfig(kind string, index int) server.PointConfig {
	v := variations[kind]
	c := classes[kind]
	if kind == kindBinary && index >= points {
		c = assigned[index-points]
	}
	return server.PointConfig{Class: c, StaticVariation: v[0], EventVariation: v[1]}
}

// update changes points as one batch of events, and records them.
func (d *device) update(changes []event) error {
	if len(changes) == 0 {
		return errors.New("no change to make")
	}
	now := app.TimestampOf(d.srv.Now())
	wall := time.Now()
	err := d.srv.Database().Batch(func(b *server.Batch) error {
		for i := range changes {
			c := &changes[i]
			_, f := valueFlags(d.values[c.kind][c.index])
			v := valueOf(c.kind, c.value, f, now)
			if err := b.Update(pointTypes[c.kind], uint32(c.index), v, server.EventForce); err != nil {
				return fmt.Errorf("%s %d: %w", c.kind, c.index, err)
			}
			d.values[c.kind][c.index] = v
			c.time, c.wall = now, wall
		}
		return nil
	})
	if err != nil {
		return err
	}
	var evs []event
	for _, c := range changes {
		if classes[c.kind] != 0 {
			evs = append(evs, c)
		}
	}
	d.batches = append(d.batches, evs)
	d.checked = 0
	return nil
}

// next is a new value of a point: binary points toggle, double-bit points
// alternate between off and on, counters count up, analogs step.
func (d *device) next(kind string, index int) float64 {
	x, _ := valueFlags(d.values[kind][index])
	switch kind {
	case kindBinary, kindBinaryOutput:
		return 1 - x
	case kindDoubleBit:
		if x == float64(app.DoubleBitOn) {
			return float64(app.DoubleBitOff)
		}
		return float64(app.DoubleBitOn)
	case kindCounter, kindFrozenCounter:
		return x + 1
	default:
		d.counter++
		return 100 + d.counter
	}
}

// changes makes n changes of a kind, one point after another.
func (d *device) changes(kind string, n int) []event {
	cs := make([]event, 0, n)
	pending := map[int]float64{}
	for i := range n {
		idx := i % points
		x, ok := pending[idx]
		if !ok {
			x, _ = valueFlags(d.values[kind][idx])
		}
		saved := d.values[kind][idx]
		d.values[kind][idx] = valueOf(kind, x, 0, 0)
		y := d.next(kind, idx)
		d.values[kind][idx] = saved
		pending[idx] = y
		cs = append(cs, event{kind: kind, index: idx, value: y})
	}
	return cs
}

func (d *device) setFlags(kind string, index int, f app.Flags) error {
	x, _ := valueFlags(d.values[kind][index])
	v := valueOf(kind, x, f, app.TimestampOf(d.srv.Now()))
	mode := server.EventOnChange
	if classes[kind] == 0 {
		mode = server.EventSuppress
	}
	if err := d.srv.Database().Update(pointTypes[kind], uint32(index), v, mode); err != nil {
		return err
	}
	d.values[kind][index] = v
	return nil
}

// handler executes the controls of binary and analog outputs 0..points-1.
type handler struct {
	server.NopHandler
	d *device
}

func (h *handler) check(c server.Command) app.CommandStatus {
	d := h.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if int(c.Index) >= points {
		return app.StatusNotSupported
	}
	switch c.Value.(type) {
	case app.CROB:
		if d.removed[kindBinaryOutput] {
			return app.StatusNotSupported
		}
		if !d.global || d.local[int(c.Index)] {
			return app.StatusLocal
		}
	case app.AnalogOutput:
		if d.removed[kindAnalogOutput] {
			return app.StatusNotSupported
		}
		// the analog outputs are 16-bit (g40v2)
		if v := c.Value.(app.AnalogOutput).Value; v < math.MinInt16 || v > math.MaxInt16 {
			return app.StatusOutOfRange
		}
	default:
		return app.StatusNotSupported
	}
	return app.StatusSuccess
}

func (h *handler) Select(_ context.Context, c server.Command) app.CommandStatus {
	return h.check(c)
}

func (h *handler) Operate(_ context.Context, c server.Command, _ server.OperateType) app.CommandStatus {
	if s := h.check(c); s != app.StatusSuccess {
		return s
	}
	d := h.d
	d.mu.Lock()
	defer d.mu.Unlock()
	idx := int(c.Index)
	switch v := c.Value.(type) {
	case app.CROB:
		d.ops = append(d.ops, operation{kindBinaryOutput, idx})
		x, f := valueFlags(d.values[kindBinaryOutput][idx])
		switch {
		case v.Op == app.OpLatchOn || v.TripClose == app.TCCClose:
			x = 1
		case v.Op == app.OpLatchOff || v.TripClose == app.TCCTrip:
			x = 0
		}
		nv := valueOf(kindBinaryOutput, x, f, 0)
		_ = d.srv.Database().Update(server.BinaryOutput, c.Index, nv, server.EventSuppress)
		d.values[kindBinaryOutput][idx] = nv
	case app.AnalogOutput:
		d.ops = append(d.ops, operation{kindAnalogOutput, idx})
		_, f := valueFlags(d.values[kindAnalogOutput][idx])
		nv := valueOf(kindAnalogOutput, v.Value, f, 0)
		_ = d.srv.Database().Update(server.AnalogOutput, c.Index, nv, server.EventSuppress)
		d.values[kindAnalogOutput][idx] = nv
	}
	return app.StatusSuccess
}

// Restart answers COLD_RESTART and WARM_RESTART, and restarts the
// outstation shortly after.
func (h *handler) Restart(_ context.Context, cold bool) (time.Duration, error) {
	d := h.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if cold && !d.cfg.coldRestart {
		return 0, errors.New("cold restart disabled")
	}
	srv := d.srv
	time.AfterFunc(50*time.Millisecond, srv.Restart)
	if cold {
		return time.Second, nil
	}
	return 500 * time.Millisecond, nil
}
