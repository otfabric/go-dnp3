// SPDX-License-Identifier: MIT

package server

import (
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
)

// Spec tests of the message structure of the outstation's requests and
// responses (IEEE 1815-2012 4.2, 4.3 and 4.5).

// TestSpecTable4_5_VirtualRangeKept: range codes 3 to 5 carry virtual
// addresses, codes 0 to 2 point indexes (Table 4-5, p. 33; 4.2.2.7.3.3,
// p. 34). Fitting a header to its objects picks the smallest range field of
// the same kind: a virtual range stays virtual.
func TestSpecTable4_5_VirtualRangeKept(t *testing.T) {
	objs := func(idx ...uint32) []app.Object {
		var out []app.Object
		for _, i := range idx {
			out = append(out, app.Object{Index: i, Value: app.Analog{}})
		}
		return out
	}
	for _, c := range []struct {
		q    app.Qualifier
		idx  []uint32
		want app.Qualifier
	}{
		{app.Qual1ByteVirtualStartStop, []uint32{2, 3}, app.Qual1ByteVirtualStartStop},
		{app.Qual1ByteVirtualStartStop, []uint32{300, 301}, app.Qual2ByteVirtualStartStop},
		{app.Qual4ByteVirtualStartStop, []uint32{70000}, app.Qual4ByteVirtualStartStop},
		{app.Qual4ByteVirtualStartStop, []uint32{9}, app.Qual1ByteVirtualStartStop},
		{app.Qual2ByteStartStop, []uint32{9, 10}, app.Qual1ByteStartStop},
		{app.Qual1ByteStartStop, []uint32{65535, 65536}, app.Qual4ByteStartStop},
	} {
		h := normalize(app.Header{GV: app.G30V1, Qualifier: c.q, Objects: objs(c.idx...)})
		if h.Qualifier != c.want || h.Start != c.idx[0] || h.Stop != c.idx[len(c.idx)-1] {
			t.Errorf("%#x %v: %#x %d-%d, want %#x", uint8(c.q), c.idx, uint8(h.Qualifier), h.Start, h.Stop, uint8(c.want))
		}
	}
}

// TestSpecTable4_6_ReservedQualifiers: a request with a qualifier code
// Table 4-6 (p. 34) reserves cannot be parsed: IIN2.2 (4.5.11, p. 85),
// with the request's sequence number.
func TestSpecTable4_6_ReservedQualifiers(t *testing.T) {
	m := newMaster(t)
	for i, q := range []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x1B, 0x11, 0x26, 0x3A, 0x40, 0x47, 0x59, 0x6A, 0x70, 0x7B, 0x7F, 0x86} {
		seq := byte(i % 16)
		m.sendRaw([]byte{0xC0 | seq, byte(app.FuncRead), 1, 0, q, 0, 0, 0, 0})
		f := m.recvFunc(app.FuncResponse)
		if !f.IIN.Has(app.IINParameterError) || f.Control.Seq != seq || len(f.Headers) != 0 {
			t.Errorf("qualifier %#02x: %s", q, f)
		}
	}
}

// TestSpec4_5_11_StaticReadIndexCountZero: an index-prefixed READ with a
// count of 0 names no point: nothing is reported and no point is missing,
// so no IIN2.2 either (4.5.11, p. 85).
func TestSpec4_5_11_StaticReadIndexCountZero(t *testing.T) {
	m := newMaster(t)
	for i, raw := range [][]byte{
		{0xC1, byte(app.FuncRead), 1, 0, 0x17, 0},
		{0xC2, byte(app.FuncRead), 30, 0, 0x28, 0, 0},
		{0xC3, byte(app.FuncRead), 1, 2, 0x17, 0, 30, 1, 0x28, 0, 0},
	} {
		m.sendRaw(raw)
		if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 || len(f.Headers) != 0 {
			t.Errorf("case %d: %s", i, f)
		}
	}
}

// TestSpec4_5_9_UndefinedFunctionCodes: IIN2.0 shall be set in responses
// to a request with a function code the outstation does not support
// (4.5.9, p. 84): the codes Table 4-2 (pp. 23-27) leaves undefined, 34 to
// 128, and INITIALIZE_DATA, which the outstation does not support without
// an ApplicationHandler. The response has the request's sequence number.
func TestSpec4_5_9_UndefinedFunctionCodes(t *testing.T) {
	m := newMaster(t)
	codes := []byte{byte(app.FuncInitializeData)}
	for fc := 34; fc <= 128; fc++ {
		codes = append(codes, byte(fc))
	}
	for i, fc := range codes {
		seq := byte(i % 16)
		m.sendRaw([]byte{0xC0 | seq, fc})
		f := m.recvFunc(app.FuncResponse)
		if f.IIN&app.IINRequestErrors != app.IINNoFuncCodeSupport || f.Control.Seq != seq || len(f.Headers) != 0 {
			t.Fatalf("function code %d: %s", fc, f)
		}
	}
}

// TestSpec4_5_14_ConfigCorrupt: IIN2.5 (4.5.14, p. 88) is optional; the
// application sets and clears it with SetIndications.
func TestSpec4_5_14_ConfigCorrupt(t *testing.T) {
	m := newMaster(t)
	m.srv.SetIndications(app.IINConfigCorrupt, true)
	m.send(req(1, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINConfigCorrupt) {
		t.Fatalf("set: %s", f)
	}
	m.srv.SetIndications(app.IINConfigCorrupt, false)
	m.send(req(2, app.FuncRead, app.ClassHeaders(0)...))
	if f := m.recvFunc(app.FuncResponse); f.IIN.Has(app.IINConfigCorrupt) {
		t.Fatalf("cleared: %s", f)
	}
}

// TestSpec4_5_15_ReservedIINAlwaysClear: IIN2.6 and IIN2.7 shall always
// be returned cleared to 0 (4.5.15, 4.5.16, p. 88), whatever the
// application or its handler ask for.
func TestSpec4_5_15_ReservedIINAlwaysClear(t *testing.T) {
	const reserved = app.IINReserved1 | app.IINReserved2
	m := newMaster(t, WithHandler(specApp{iin: reserved | app.IINDeviceTrouble}))
	m.srv.SetIndications(reserved, true)
	for i, r := range []*app.Fragment{req(1, app.FuncRead, app.ClassHeaders(0)...), req(2, app.FuncInitializeApplication), req(3, app.FuncSaveConfiguration)} {
		m.send(r)
		if f := m.recvFunc(app.FuncResponse); f.IIN&(reserved|app.IINDeviceTrouble) != 0 {
			t.Errorf("request %d: %s", i+1, f)
		}
	}
}

// TestSpec4_5_8_DeviceRestartOnlyCleared: the only permissible method to
// clear IIN1.7 is for the master to write 0 to g80v1 index 7 (4.5.8,
// p. 84); a write of 1 is refused with IIN2.2 and the bit stays set.
func TestSpec4_5_8_DeviceRestartOnlyCleared(t *testing.T) {
	m := newMaster(t)
	m.send(req(1, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{Value: true})))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINParameterError) || !f.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("write of 1: %s", f)
	}
	m.send(req(2, app.FuncWrite, app.Ranged(app.G80V1, 7, app.Binary{})))
	if f := m.recvFunc(app.FuncResponse); f.IIN&app.IINRequestErrors != 0 || f.IIN.Has(app.IINDeviceRestart) {
		t.Fatalf("write of 0: %s", f)
	}
}

// TestSpec4_5_2_ClassBitsOfEventsNotInResponse: IIN1.1 to IIN1.3 are set
// when there are events of the class that the current response does not
// include (4.5.2 to 4.5.4, p. 82). Events in the response clear them;
// events left out by a count set them; the events of a response whose
// confirmation did not come are not in the next response, which sets them
// again. Events sent in an unsolicited response that awaits its
// confirmation are reported: they do not set the bits.
func TestSpec4_5_2_ClassBitsOfEventsNotInResponse(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline})
	_ = db.UpdateBinaryInput(1, app.Binary{Value: true, Flags: app.FlagOnline})
	m.send(req(1, app.FuncRead, app.CountOf(app.G60V2, 1)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || !f.IIN.Has(app.IINClass1Events) {
		t.Fatalf("one of two events: %s", f)
	}
	m.send(confirm(1, false))
	m.send(req(2, app.FuncRead, app.AllObjects(app.G60V2)))
	if f := m.recvFunc(app.FuncResponse); len(f.Headers) != 1 || f.IIN.Has(app.IINClass1Events) {
		t.Fatalf("the last event: %s", f)
	}
	m.send(req(3, app.FuncRead, app.AllObjects(app.G80V1)))
	if f := m.recvFunc(app.FuncResponse); !f.IIN.Has(app.IINClass1Events) {
		t.Fatalf("a response without the unconfirmed event: %s", f)
	}

	u := newMaster(t, WithUnsolicited(Unsolicited{Enabled: true, Classes: []Class{2}}), WithConfirmTimeout(5*time.Second))
	null := u.recvFunc(app.FuncUnsolicitedResponse)
	u.send(confirm(null.Control.Seq, true))
	_ = u.srv.Database().UpdateAnalogInput(0, app.Analog{Value: 50, Flags: app.FlagOnline})
	ev := u.recvFunc(app.FuncUnsolicitedResponse)
	if len(ev.Headers) != 1 || ev.IIN.Has(app.IINClass2Events) {
		t.Fatalf("unsolicited %s", ev)
	}
	// Not a READ, which waits for the confirmation (4.6.6 Rule 16, p. 93).
	u.send(req(1, app.FuncDelayMeasure))
	if f := u.recvFunc(app.FuncResponse); f.IIN.Has(app.IINClass2Events) {
		t.Fatalf("while the unsolicited response awaits its confirmation: %s", f)
	}
	u.send(confirm(ev.Control.Seq, true))
}

// TestSpec4_3_Rule2_TwoOctetFragments: all devices shall accept fragments
// as small as 2 octets (4.3 Rule 2, p. 38): a request of only its
// application header.
func TestSpec4_3_Rule2_TwoOctetFragments(t *testing.T) {
	m := newMaster(t)
	m.sendRaw([]byte{0xC1, byte(app.FuncDelayMeasure)})
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 1 || len(f.Headers) != 1 || f.Headers[0].GV != app.G52V2 {
		t.Fatalf("DELAY_MEASURE: %s", f)
	}
	m.sendRaw([]byte{0xC2, byte(app.FuncRead)})
	if f := m.recvFunc(app.FuncResponse); f.Control.Seq != 2 || f.IIN&app.IINRequestErrors != 0 || len(f.Headers) != 0 {
		t.Fatalf("READ without headers: %s", f)
	}
}

// TestSpec4_3_Rules8_9_15_24_MultiFragmentResponse: of a response in
// several fragments, FIR is set in the first (4.3 Rule 8, p. 39) and FIN in
// the last (Rule 9); the first has the request's sequence number and each
// next one the previous plus one, modulo 16 (Rule 15); every fragment but
// the last asks for confirmation (Rule 24, p. 40), the next being sent
// when it comes. No fragment exceeds the configured size (Rule 1, p. 38).
func TestSpec4_3_Rules8_9_15_24_MultiFragmentResponse(t *testing.T) {
	const maxTx = 249
	m := newMaster(t, WithMaxFragment(maxTx, 2048))
	db := m.srv.Database()
	for i := range uint32(200) {
		_ = db.AddAnalogInput(10+i, PointConfig{StaticVariation: 1}, app.Analog{Value: float64(i), Flags: app.FlagOnline})
	}
	m.send(req(14, app.FuncRead, app.ClassHeaders(0)...))
	var got []*app.Fragment
	seq := uint8(14)
	for {
		f := m.recvFunc(app.FuncResponse)
		got = append(got, f)
		if b, _ := f.Encode(); len(b) > maxTx {
			t.Fatalf("fragment %d: %d octets", len(got), len(b))
		}
		if f.Control.FIR != (len(got) == 1) || f.Control.Seq != seq {
			t.Fatalf("fragment %d: %s, want seq %d", len(got), f, seq)
		}
		if f.Control.FIN {
			break
		}
		if !f.Control.CON {
			t.Fatalf("fragment %d without CON: %s", len(got), f)
		}
		m.none(100 * time.Millisecond) // the next only after the confirmation
		m.send(confirm(seq, false))
		seq = app.NextSeq(seq)
	}
	if len(got) < 4 || got[len(got)-1].Control.CON {
		t.Fatalf("%d fragments, last %s", len(got), got[len(got)-1])
	}
	n := 0
	for _, f := range got {
		for _, h := range f.Headers {
			if h.GV.Group() == 30 {
				n += len(h.Objects)
			}
		}
	}
	if n != 201 {
		t.Fatalf("%d analog inputs in %d fragments", n, len(got))
	}
}

// TestSpecTable4_8_ResponseQualifiers: Table 4-8 (p. 35): the outstation
// reports static objects with qualifier 0x00 or 0x01, a single quantity
// without an index (time and date, a time delay, a CTO) with 0x07, and
// events, and points read by index, with 0x17 or 0x28.
func TestSpecTable4_8_ResponseQualifiers(t *testing.T) {
	m := newMaster(t)
	db := m.srv.Database()
	_ = db.AddBinaryInput(300, PointConfig{Class: 1, EventVariation: 3}, app.Binary{Flags: app.FlagOnline})
	type want struct {
		gv app.GroupVariation
		q  app.Qualifier
	}
	check := func(seq uint8, r *app.Fragment, ws ...want) {
		t.Helper()
		m.send(r)
		f := m.recvFunc(app.FuncResponse)
		if len(f.Headers) != len(ws) {
			t.Fatalf("%s: %s", r, f)
		}
		for i, w := range ws {
			if h := f.Headers[i]; h.GV != w.gv || h.Qualifier != w.q {
				t.Errorf("%s: header %d %s %#x, want %s %#x", r, i, h.GV, uint8(h.Qualifier), w.gv, uint8(w.q))
			}
		}
		if f.Control.CON {
			m.send(confirm(seq, false))
		}
	}
	check(1, req(1, app.FuncRead, app.IndexRange(app.G1V2, 0, 1), app.IndexRange(app.G1V2, 300, 300)),
		want{app.G1V2, app.Qual1ByteStartStop}, want{app.G1V2, app.Qual2ByteStartStop})
	check(2, req(2, app.FuncRead, app.IndexList(app.G1V2, 1, 0)), want{app.G1V2, app.Qual1ByteIndexCount})
	check(3, req(3, app.FuncRead, app.IndexList(app.G1V2, 300)), want{app.G1V2, app.Qual2ByteIndexCount})
	check(4, req(4, app.FuncRead, app.CountOf(app.G50V1, 1)), want{app.G50V1, app.Qual1ByteCount})
	check(5, req(5, app.FuncDelayMeasure), want{app.G52V2, app.Qual1ByteCount})
	check(6, req(6, app.FuncRead, app.AllObjects(app.G80V1)), want{app.G80V1, app.Qual1ByteStartStop})
	_ = db.UpdateBinaryInput(0, app.Binary{Flags: app.FlagOnline, Time: 1000})
	_ = db.UpdateBinaryInput(300, app.Binary{Value: true, Flags: app.FlagOnline, Time: 1001})
	check(7, req(7, app.FuncRead, app.AllObjects(app.G60V2)),
		want{app.G2V2, app.Qual1ByteIndexCount}, want{app.G51V1, app.Qual1ByteCount}, want{app.G2V3, app.Qual2ByteIndexCount})
}
