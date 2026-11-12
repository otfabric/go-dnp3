// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// levelRow is one row of the Request column of IEEE 1815-2012 Tables 14-2
// (L1, pp. 398-399), 14-3 (L2, pp. 401-403) and 14-4 (L3, pp. 405-411),
// with Tables 12-1 to 12-32 (pp. 351-361): a request an outstation of that
// level shall parse (12.1.1.2, p. 351; 14.2.2, pp. 394-395).
type levelRow struct {
	level       int
	name        string
	fc          app.FunctionCode
	hs          []app.Header
	events      bool // update every point first, so that each type has events
	selectFirst bool // SELECT the same objects first (OPERATE)
	noAck       bool // a _NR function: no response
	echo        bool // a control: the response echoes the request
	groups      []uint8
}

// levelRows returns the L1 to L3 request rows.
func levelRows() []levelRow {
	var rows []levelRow
	add := func(r levelRow) { rows = append(rows, r) }
	G := app.GV
	rng := func(gv app.GroupVariation, q app.Qualifier) app.Header {
		return app.Header{GV: gv, Qualifier: q, Start: 0, Stop: 3}
	}
	cnt := func(gv app.GroupVariation, q app.Qualifier, n uint32) app.Header {
		return app.Header{GV: gv, Qualifier: q, Count: n}
	}
	q00, q01, q07, q08, q17, q28 := app.Qual1ByteStartStop, app.Qual2ByteStartStop, app.Qual1ByteCount,
		app.Qual2ByteCount, app.Qual1ByteIndexCount, app.Qual2ByteIndexCount

	// Static reads: group, variation, the lowest level of 00/01 and of 06.
	for _, s := range []struct {
		g, v     uint8
		rng, all int
	}{
		{1, 0, 3, 2}, {1, 1, 3, 3}, {1, 2, 3, 3}, // Table 12-1, p. 352
		{10, 0, 3, 1}, {10, 2, 3, 3}, // Table 12-6, p. 353
		{20, 0, 3, 2}, {20, 1, 3, 3}, {20, 2, 3, 3}, {20, 5, 3, 3}, {20, 6, 3, 3}, // Table 12-10, p. 355
		{21, 0, 3, 2}, {21, 1, 3, 3}, {21, 2, 3, 3}, {21, 9, 3, 3}, {21, 10, 3, 3}, // Table 12-11, p. 355
		{30, 0, 3, 2}, {30, 1, 3, 3}, {30, 2, 3, 3}, {30, 3, 3, 3}, {30, 4, 3, 3}, // Table 12-14, p. 356
		{40, 0, 3, 1}, {40, 1, 3, 3}, {40, 2, 3, 3}, // Table 12-19, p. 358
	} {
		gv := G(s.g, s.v)
		add(levelRow{level: s.rng, name: fmt.Sprintf("%s READ 00", gv), fc: app.FuncRead, hs: []app.Header{rng(gv, q00)}, groups: []uint8{s.g}})
		add(levelRow{level: s.rng, name: fmt.Sprintf("%s READ 01", gv), fc: app.FuncRead, hs: []app.Header{rng(gv, q01)}, groups: []uint8{s.g}})
		add(levelRow{level: s.all, name: fmt.Sprintf("%s READ 06", gv), fc: app.FuncRead, hs: []app.Header{app.AllObjects(gv)}, groups: []uint8{s.g}})
	}
	// Event reads: group, variation, lowest level.
	for _, e := range []struct {
		g, v  uint8
		level int
	}{
		{2, 0, 2}, {2, 1, 2}, {2, 2, 2}, {2, 3, 2}, // Table 12-2, p. 352
		{22, 0, 2}, {22, 1, 3}, {22, 2, 3}, // Table 12-12, p. 356
		{23, 0, 3}, {23, 1, 3}, {23, 2, 3}, // Table 12-13, p. 356
		{32, 0, 2}, {32, 1, 3}, {32, 2, 3}, // Table 12-16, p. 357
	} {
		gv := G(e.g, e.v)
		add(levelRow{level: e.level, name: fmt.Sprintf("%s READ 06", gv), fc: app.FuncRead, hs: []app.Header{app.AllObjects(gv)}, events: true, groups: []uint8{e.g}})
		add(levelRow{level: e.level, name: fmt.Sprintf("%s READ 07", gv), fc: app.FuncRead, hs: []app.Header{cnt(gv, q07, 2)}, events: true, groups: []uint8{e.g}})
		add(levelRow{level: e.level, name: fmt.Sprintf("%s READ 08", gv), fc: app.FuncRead, hs: []app.Header{cnt(gv, q08, 2)}, events: true, groups: []uint8{e.g}})
	}
	// Class reads (Table 12-27, p. 361).
	add(levelRow{level: 1, name: "g60v1 READ 06", fc: app.FuncRead, hs: []app.Header{app.AllObjects(app.G60V1)}, groups: []uint8{1, 10, 20, 30, 40}})
	for v := uint8(2); v <= 4; v++ {
		gv := G(60, v)
		add(levelRow{level: 1, name: fmt.Sprintf("%s READ 06", gv), fc: app.FuncRead, hs: []app.Header{app.AllObjects(gv)}, events: true})
		add(levelRow{level: 1, name: fmt.Sprintf("%s READ 07", gv), fc: app.FuncRead, hs: []app.Header{cnt(gv, q07, 3)}, events: true})
		add(levelRow{level: 1, name: fmt.Sprintf("%s READ 08", gv), fc: app.FuncRead, hs: []app.Header{cnt(gv, q08, 3)}, events: true})
	}
	add(levelRow{level: 1, name: "integrity poll", fc: app.FuncRead, hs: app.ClassHeaders(1, 2, 3, 0), events: true, groups: []uint8{2, 22, 32, 1, 30}})
	// Internal indications (Table 12-26, p. 361).
	add(levelRow{level: 3, name: "g80v1 READ 00", fc: app.FuncRead, hs: []app.Header{{GV: app.G80V1, Qualifier: q00, Start: 0, Stop: 15}}, groups: []uint8{80}})
	add(levelRow{level: 3, name: "g80v1 READ 01", fc: app.FuncRead, hs: []app.Header{{GV: app.G80V1, Qualifier: q01, Start: 0, Stop: 15}}, groups: []uint8{80}})
	add(levelRow{level: 1, name: "g80v1 WRITE 00", fc: app.FuncWrite, hs: []app.Header{app.Ranged(app.G80V1, 7, app.Binary{})}})
	// Time (Table 12-23, p. 360) and delay (Table 12-25, p. 361).
	add(levelRow{level: 3, name: "g50v1 READ 07", fc: app.FuncRead, hs: []app.Header{cnt(app.G50V1, q07, 1)}, groups: []uint8{50}})
	add(levelRow{level: 1, name: "g50v1 WRITE 07", fc: app.FuncWrite, hs: []app.Header{app.Counted(app.G50V1, app.AbsoluteTime{Time: app.Now()})}})
	add(levelRow{level: 1, name: "DELAY_MEASURE", fc: app.FuncDelayMeasure, groups: []uint8{52}})
	add(levelRow{level: 1, name: "COLD_RESTART", fc: app.FuncColdRestart, groups: []uint8{52}})
	// Controls (Table 12-8, p. 354; Table 12-20, p. 358).
	for _, fc := range []app.FunctionCode{app.FuncSelect, app.FuncOperate, app.FuncDirectOperate, app.FuncDirectOperateNoAck} {
		for _, q := range []app.Qualifier{q17, q28} {
			for _, c := range []struct {
				gv    app.GroupVariation
				v     app.Value
				level int
			}{{app.G12V1, app.CROB{Op: app.OpLatchOn, Count: 1}, 1}, {app.G41V1, app.AnalogOutput{Value: 3}, 3}, {app.G41V2, app.AnalogOutput{Value: 3}, 1}} {
				h := app.Header{GV: c.gv, Qualifier: q, Objects: []app.Object{{Index: 1, Value: c.v}}}
				add(levelRow{level: c.level, name: fmt.Sprintf("%s %s %#02x", c.gv, fc, uint8(q)), fc: fc, hs: []app.Header{h},
					selectFirst: fc == app.FuncOperate, noAck: fc == app.FuncDirectOperateNoAck, echo: true, groups: []uint8{c.gv.Group()}})
			}
		}
	}
	// Freezes (Table 12-10, p. 355).
	for _, fc := range []app.FunctionCode{app.FuncImmediateFreeze, app.FuncImmediateFreezeNoAck, app.FuncFreezeClear, app.FuncFreezeClearNoAck} {
		nr := fc == app.FuncImmediateFreezeNoAck || fc == app.FuncFreezeClearNoAck
		add(levelRow{level: 2, name: fmt.Sprintf("g20v0 %s 06", fc), fc: fc, hs: []app.Header{app.AllObjects(app.G20V0)}, noAck: nr})
		add(levelRow{level: 3, name: fmt.Sprintf("g20v0 %s 00", fc), fc: fc, hs: []app.Header{rng(app.G20V0, q00)}, noAck: nr})
		add(levelRow{level: 3, name: fmt.Sprintf("g20v0 %s 01", fc), fc: fc, hs: []app.Header{rng(app.G20V0, q01)}, noAck: nr})
	}
	// ASSIGN_CLASS (Tables 12-1, 12-10, 12-11, 12-14) of the L3 point
	// types, to each class.
	for v := uint8(1); v <= 4; v++ {
		for _, g := range []uint8{1, 20, 21, 30} {
			class := app.AllObjects(G(60, v))
			for _, h := range []app.Header{app.AllObjects(G(g, 0)), rng(G(g, 0), q00), rng(G(g, 0), q01)} {
				add(levelRow{level: 3, name: fmt.Sprintf("ASSIGN_CLASS g60v%d g%dv0 %#02x", v, g, uint8(h.Qualifier)), fc: app.FuncAssignClass, hs: []app.Header{class, h}})
			}
		}
	}
	// Unsolicited control (Table 12-27, p. 361).
	for v := uint8(2); v <= 4; v++ {
		add(levelRow{level: 3, name: fmt.Sprintf("DISABLE_UNSOLICITED g60v%d", v), fc: app.FuncDisableUnsolicited, hs: []app.Header{app.AllObjects(G(60, v))}})
		add(levelRow{level: 3, name: fmt.Sprintf("ENABLE_UNSOLICITED g60v%d", v), fc: app.FuncEnableUnsolicited, hs: []app.Header{app.AllObjects(G(60, v))}})
	}
	return rows
}

// levelGroups are the groups of the Response columns of Tables 14-2 to 14-4.
var levelGroups = map[uint8]bool{1: true, 2: true, 10: true, 12: true, 20: true, 21: true, 22: true, 23: true,
	30: true, 32: true, 40: true, 41: true, 50: true, 51: true, 52: true, 80: true}

// levelQualifier checks a response header against Table 14-1 (p. 396):
// 00/01 for static objects, 17/28 for events and echoed controls, 07 for a
// single object without an index (g50 to g52).
func levelQualifier(r levelRow, h app.Header) error {
	q := h.Qualifier
	ok := true
	switch g := h.GV.Group(); {
	case r.echo:
		ok = q == r.hs[0].Qualifier
	case g == 1, g == 10, g == 20, g == 21, g == 30, g == 40, g == 80:
		ok = q == app.Qual1ByteStartStop || q == app.Qual2ByteStartStop
	case g == 2, g == 22, g == 23, g == 32:
		ok = q == app.Qual1ByteIndexCount || q == app.Qual2ByteIndexCount
	case g == 50, g == 51, g == 52:
		ok = q == app.Qual1ByteCount && len(h.Objects) == 1
	}
	if !ok || !levelGroups[h.GV.Group()] {
		return fmt.Errorf("%s with qualifier %#02x", h.GV, uint8(q))
	}
	return nil
}

// levelHandler accepts controls and restarts.
type levelHandler struct{ NopHandler }

func (levelHandler) Select(context.Context, Command) app.CommandStatus { return app.StatusSuccess }
func (levelHandler) Operate(context.Context, Command, OperateType) app.CommandStatus {
	return app.StatusSuccess
}
func (levelHandler) Restart(context.Context, bool) (time.Duration, error) {
	return 2 * time.Second, nil
}

// levelMaster is an outstation with points of every L1 to L3 type, at
// indexes 0 to 3, events in classes 1 to 3, and unsolicited responses
// enabled but no class reported unsolicited.
func levelMaster(t *testing.T) *master {
	t.Helper()
	m := newMaster(t, WithHandler(levelHandler{}), WithTimeSync(time.Hour), WithUnsolicited(Unsolicited{Enabled: true}))
	null := m.recvFunc(app.FuncUnsolicitedResponse)
	m.send(confirm(null.Control.Seq, true))
	db := m.srv.Database()
	for _, p := range levelPoints {
		for i := range uint32(4) {
			if err := db.Add(p.t, i, PointConfig{Class: p.class}, levelValue(p.t, i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return m
}

var levelPoints = []struct {
	t     PointType
	class Class
}{
	{BinaryInput, 1}, {BinaryOutput, 0}, {Counter, 3}, {FrozenCounter, 3}, {AnalogInput, 2}, {AnalogOutput, 0},
}

func levelValue(t PointType, x uint32) app.Value {
	switch t {
	case BinaryInput, BinaryOutput:
		return app.Binary{Value: x%2 == 1, Flags: app.FlagOnline}
	case Counter, FrozenCounter:
		return app.Counter{Value: x, Flags: app.FlagOnline}
	default:
		return app.Analog{Value: float64(x), Flags: app.FlagOnline}
	}
}

// TestSubsetLevelTables sends every L1 to L3 row of the Request columns of
// Tables 14-2 to 14-4 to the outstation: each is parsed and answered
// without a request error (IIN2.0 to IIN2.2), the _NR rows without a
// response, and the response holds the objects the row asks for, with the
// qualifiers of Table 14-1 (p. 396). go-dnp3 claims no subset level
// (LIMITATIONS.md); this checks the rows a level 3 outstation shall parse.
func TestSubsetLevelTables(t *testing.T) {
	for _, r := range levelRows() {
		if r.level > 3 {
			continue
		}
		t.Run(fmt.Sprintf("L%d %s", r.level, r.name), func(t *testing.T) {
			m := levelMaster(t)
			if r.events {
				db := m.srv.Database()
				for _, p := range levelPoints {
					for i := range uint32(4) {
						_ = db.Update(p.t, i, levelValue(p.t, i+7), EventForce)
					}
				}
			}
			seq := uint8(1)
			if r.selectFirst {
				m.send(req(seq, app.FuncSelect, r.hs...))
				m.recvFunc(app.FuncResponse)
				seq++
			}
			m.send(req(seq, r.fc, r.hs...))
			if r.noAck {
				// Answered is only the request after it.
				m.send(req(seq+1, app.FuncDelayMeasure))
				if f := m.recvFunc(app.FuncResponse); f.Control.Seq != seq+1 {
					t.Fatalf("%s answered: %s", r.fc, f)
				}
				return
			}
			seen := map[uint8]bool{}
			for {
				f := m.recvFunc(app.FuncResponse)
				if f.IIN&app.IINRequestErrors != 0 {
					t.Fatalf("IIN %s", f.IIN)
				}
				for _, h := range f.Headers {
					seen[h.GV.Group()] = true
					if err := levelQualifier(r, h); err != nil {
						t.Error(err)
					}
				}
				if f.Control.FIN {
					break
				}
				m.send(confirm(f.Control.Seq, false))
			}
			for _, g := range r.groups {
				if !seen[g] {
					t.Errorf("no g%d in the response", g)
				}
			}
		})
	}
}
