//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
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
	Files           []fixtureFile  `json:"files"`
	Directories     []string       `json:"directories"`
}

// fixtureFile is a file the outstation serves (fixture format 1.1).
type fixtureFile struct {
	Name    string `json:"name"`
	Content string `json:"content"` // hex
}

func (f fixtureFile) data() []byte {
	b, _ := hex.DecodeString(f.Content)
	return b
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
	f     *fixture
	srv   *server.Server
	files *fileStore

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
	if len(f.Files) > 0 || len(f.Directories) > 0 {
		st.files = newFileStore(f)
		o = append(o, server.WithFileServer(st.files))
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

// fileStore serves the files of a fixture as FIXTURES.md says: masters
// read, list, describe, write into existing directories and delete. The
// files live as long as the station.
type fileStore struct {
	mu      sync.Mutex
	files   map[string][]byte
	dirs    map[string]bool
	created app.Timestamp
}

func newFileStore(f *fixture) *fileStore {
	s := &fileStore{files: map[string][]byte{}, dirs: map[string]bool{"/": true}, created: app.TimestampOf(time.Now())}
	addDir := func(d string) {
		for ; d != "/"; d = path.Dir(d) {
			s.dirs[d] = true
		}
	}
	for _, ff := range f.Files {
		name := path.Clean(ff.Name)
		s.files[name] = ff.data()
		addDir(path.Dir(name))
	}
	for _, d := range f.Directories {
		addDir(path.Clean(d))
	}
	return s
}

func fileName(name string) string { return path.Clean("/" + name) }

func (s *fileStore) descriptor(name string, full bool) app.FileDescriptor {
	shown := name
	if !full {
		shown = path.Base(name)
	}
	if s.dirs[name] {
		return app.FileDescriptor{Name: shown, Type: app.FileTypeDirectory, Created: s.created, Permissions: 0o755}
	}
	return app.FileDescriptor{Name: shown, Type: app.FileTypeSimple, Size: uint32(len(s.files[name])), Created: s.created, Permissions: 0o644}
}

func (s *fileStore) Open(_ context.Context, req server.FileRequest) (server.File, app.FileStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := fileName(req.Name)
	switch req.Mode {
	case app.FileModeRead:
		if s.dirs[name] {
			var children []string
			for n := range s.files {
				if path.Dir(n) == name {
					children = append(children, n)
				}
			}
			for d := range s.dirs {
				if d != "/" && path.Dir(d) == name {
					children = append(children, d)
				}
			}
			sort.Strings(children)
			var b []byte
			for _, c := range children {
				b, _ = app.AppendFileDescriptor(b, s.descriptor(c, false))
			}
			return &storeFile{r: bytes.NewReader(b), size: len(b)}, app.FileSuccess
		}
		data, ok := s.files[name]
		if !ok {
			return nil, app.FileNotFound
		}
		return &storeFile{r: bytes.NewReader(data), size: len(data)}, app.FileSuccess
	case app.FileModeWrite, app.FileModeAppend:
		if s.dirs[name] {
			return nil, app.FilePermissionDenied
		}
		if !s.dirs[path.Dir(name)] {
			return nil, app.FileNotFound
		}
		f := &storeFile{store: s, name: name}
		if req.Mode == app.FileModeAppend {
			f.w.Write(s.files[name])
		}
		return f, app.FileSuccess
	default:
		return nil, app.FileInvalidMode
	}
}

func (s *fileStore) Delete(_ context.Context, name string, _ uint32) app.FileStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = fileName(name)
	if _, ok := s.files[name]; !ok {
		if s.dirs[name] {
			return app.FilePermissionDenied
		}
		return app.FileNotFound
	}
	delete(s.files, name)
	return app.FileSuccess
}

func (s *fileStore) Info(_ context.Context, name string) (app.FileDescriptor, app.FileStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = fileName(name)
	if _, ok := s.files[name]; !ok && !s.dirs[name] {
		return app.FileDescriptor{}, app.FileNotFound
	}
	return s.descriptor(name, true), app.FileSuccess
}

// get returns a file's content, for checking what a master wrote.
func (s *fileStore) get(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.files[fileName(name)]
	return b, ok
}

// storeFile is a file of a fileStore being read (r) or written (w).
type storeFile struct {
	r     io.Reader
	size  int
	store *fileStore
	name  string
	w     bytes.Buffer
}

func (f *storeFile) Read(p []byte) (int, error) {
	if f.r == nil {
		return 0, fs.ErrPermission
	}
	return f.r.Read(p)
}

func (f *storeFile) Write(p []byte) (int, error) {
	if f.store == nil {
		return 0, fs.ErrPermission
	}
	return f.w.Write(p)
}

func (f *storeFile) Size() uint32 { return uint32(f.size) }

func (f *storeFile) Close(abort bool) error {
	if f.store != nil && !abort {
		f.store.mu.Lock()
		f.store.files[f.name] = bytes.Clone(f.w.Bytes())
		f.store.mu.Unlock()
	}
	return nil
}
