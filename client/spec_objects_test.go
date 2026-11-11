// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// respond encodes a response to req with the given IIN and headers.
func respond(t *testing.T, req specFrag, iin app.IIN, hs ...app.Header) []byte {
	t.Helper()
	b, err := (&app.Fragment{Control: app.SingleControl(req.f.Control.Seq), Function: app.FuncResponse, IIN: iin, Headers: hs}).Encode()
	if err != nil {
		t.Errorf("response to %s: %v", req.f, err)
	}
	return b
}

// TestSpec11_6_5_WithoutFlagsOnline: IEEE 1815-2012 clause 11.6.5 (printed
// page 329): "if a variation without flags is used, the receiving device
// shall interpret this to mean that the data is ONLINE with no exception
// conditions", and NOTE 2 of Table 11-5 (p. 326): "the master shall
// interpret this as if the flags were included with the ONLINE flag set
// and all the exception condition flags clear" (OBJECTS1-2). A variation
// with flags keeps the flags it was sent with.
func TestSpec11_6_5_WithoutFlagsOnline(t *testing.T) {
	without := []app.Header{
		app.Ranged(app.G1V1, 0, app.Binary{Value: true}),
		app.Ranged(app.G3V1, 0, app.DoubleBitBinary{Value: app.DoubleBitOn}),
		app.Ranged(app.G10V1, 0, app.Binary{Value: true}),
		app.Ranged(app.G20V5, 0, app.Counter{Value: 1}),
		app.Ranged(app.G20V6, 0, app.Counter{Value: 1}),
		app.Ranged(app.G21V9, 0, app.Counter{Value: 1}),
		app.Ranged(app.G21V10, 0, app.Counter{Value: 1}),
		app.Ranged(app.G30V3, 0, app.Analog{Value: 1}),
		app.Ranged(app.G30V4, 0, app.Analog{Value: 1}),
		app.Ranged(app.G31V5, 0, app.Analog{Value: 1}),
		app.Ranged(app.G31V6, 0, app.Analog{Value: 1}),
	}
	with := app.Ranged(app.G1V2, 0, app.Binary{Value: true, Flags: app.FlagOnline | app.FlagCommLost})
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		return [][]byte{respond(t, req, 0, append(without, with)...)}
	})
	c := specDial(t, o, quiet...)
	res, err := c.Read(testCtx(t), app.ClassHeaders(0)...)
	if err != nil {
		t.Fatal(err)
	}
	ms := res.Measurements()
	if len(ms) != len(without)+1 {
		t.Fatalf("%d measurements, want %d", len(ms), len(without)+1)
	}
	for _, m := range ms[:len(without)] {
		var flags app.Flags
		switch v := m.Value.(type) {
		case app.Binary:
			flags = v.Flags
		case app.DoubleBitBinary:
			flags = v.Flags
		case app.Counter:
			flags = v.Flags
		case app.Analog:
			flags = v.Flags
		default:
			t.Fatalf("%s: %T", m.GV, m.Value)
		}
		if flags != app.FlagOnline {
			t.Errorf("%s: flags %s, want ONLINE", m.GV, flags)
		}
	}
	if b := ms[len(without)].Value.(app.Binary); b.Flags != app.FlagOnline|app.FlagCommLost {
		t.Errorf("g1v2 flags %s", b.Flags)
	}
}

// fileStation answers the file requests of a write or a read of a file of
// size octets in blocks of block octets; readStatus, when set, answers
// the second READ instead, and the abort of the transfer is answered with
// INVALID_HANDLE, as an outstation that closed the file on the error does
// (clause 5.3.8 Rule 13, p. 120).
type fileStation struct {
	t          *testing.T
	block      uint16
	data       []byte
	readStatus app.FileStatus

	mu       sync.Mutex
	opened   app.FileCommand
	written  bytes.Buffer
	lastSeen bool
	reads    int
}

func (s *fileStation) answer(req specFrag) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(req.f.Headers) != 1 || len(req.f.Headers[0].Objects) != 1 {
		return [][]byte{empty(req, app.IINParameterError)}
	}
	v := req.f.Headers[0].Objects[0].Value
	ok := func(handle uint32) []byte {
		return respond(s.t, req, 0, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: handle, RequestID: fileRequestID}))
	}
	switch req.f.Function {
	case app.FuncOpenFile:
		s.opened = v.(app.FileCommand)
		return [][]byte{respond(s.t, req, 0, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: 7, Size: uint32(len(s.data)),
			MaxBlockSize: s.block, RequestID: s.opened.RequestID}))}
	case app.FuncWrite:
		ft := v.(app.FileTransport)
		s.written.Write(ft.Data)
		s.lastSeen = ft.Last
		return [][]byte{respond(s.t, req, 0, app.FreeFormat(app.G70V6, app.FileTransportStatus{Handle: ft.Handle, Block: ft.Block, Last: ft.Last}))}
	case app.FuncRead:
		ft := v.(app.FileTransport)
		s.reads++
		if s.readStatus != app.FileSuccess && s.reads == 2 {
			return [][]byte{respond(s.t, req, 0, app.FreeFormat(app.G70V6, app.FileTransportStatus{Handle: ft.Handle, Block: ft.Block, Status: s.readStatus}))}
		}
		start := min(int(ft.Block)*int(s.block), len(s.data))
		end := min(start+int(s.block), len(s.data))
		return [][]byte{respond(s.t, req, 0, app.FreeFormat(app.G70V5, app.FileTransport{Handle: ft.Handle, Block: ft.Block,
			Last: end == len(s.data), Data: s.data[start:end]}))}
	case app.FuncCloseFile:
		return [][]byte{ok(7)}
	case app.FuncAbortFile:
		return [][]byte{respond(s.t, req, 0, app.FreeFormat(app.G70V4, app.FileCommandStatus{Handle: 7, RequestID: fileRequestID, Status: app.FileInvalidHandle}))}
	default:
		return [][]byte{empty(req, app.IINNoFuncCodeSupport)}
	}
}

// TestSpec4_4_17_2_1_WriteFileRequest: clause 4.4.17.2.1 (printed page 68):
// for a write, "The time of creation and permissions fields are set to
// appropriate values that the outstation shall use for attributes of the
// new file", and "The file size field [...] specifies the total number of
// file octets that shall be transferred by all of the write requests
// combined" (OBJECTS2-29); "The maximum block size field is set to the
// maximum number of octets that the master shall send in each write
// request message", which WithMaxRequestFragment lowers so that each
// request fits (clause 4.3 Rule 4, p. 39).
func TestSpec4_4_17_2_1_WriteFileRequest(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 6e6, time.UTC)
	s := &fileStation{t: t, block: 1024}
	o := newSpecOutstation(t, s.answer)
	c := specDial(t, o, append(quiet, WithMaxRequestFragment(249))...)
	long := bytes.Repeat([]byte("0123456789"), 100) // 1000 octets
	n, err := c.WriteFile(testCtx(t), "f", bytes.NewReader(long), 700, FileOptions{Created: created, Permissions: 0o640})
	if err != nil || n != 700 {
		t.Fatalf("WriteFile: %d %v", n, err)
	}
	s.mu.Lock()
	if !bytes.Equal(s.written.Bytes(), long[:700]) || !s.lastSeen {
		t.Fatalf("outstation got %d octets, last %t", s.written.Len(), s.lastSeen)
	}
	if s.opened.Created.Time() != created || s.opened.Size != 700 || s.opened.Permissions != 0o640 {
		t.Fatalf("OPEN_FILE %+v", s.opened)
	}
	if want := uint16(249 - writeOverhead); s.opened.MaxBlockSize != want {
		t.Fatalf("OPEN_FILE block size %d, want %d", s.opened.MaxBlockSize, want)
	}
	s.mu.Unlock()
	for _, f := range o.sent() {
		if len(f.raw) > 249 {
			t.Fatalf("%s request of %d octets", f.f.Function, len(f.raw))
		}
	}

	// Without a time of creation, the time of the request.
	before := time.Now().Truncate(time.Millisecond)
	if _, err := c.WriteFile(testCtx(t), "g", bytes.NewReader([]byte("abc")), 3, FileOptions{}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	if at := s.opened.Created.Time(); at.Before(before) || at.After(time.Now()) {
		t.Fatalf("time of creation %v, request at %v", at, before)
	}
	s.mu.Unlock()

	// For a read, the size and the time of creation are zero.
	s.data = []byte("hello")
	var out bytes.Buffer
	if _, err := c.ReadFile(testCtx(t), "h", &out, FileOptions{}); err != nil || out.String() != "hello" {
		t.Fatalf("ReadFile: %q %v", out.String(), err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opened.Created != 0 || s.opened.Size != 0 || s.opened.Mode != app.FileModeRead {
		t.Fatalf("OPEN_FILE for reading %+v", s.opened)
	}
}

// TestSpecA_27_5_ReadRequests: Annex A.27.5.2.2 (printed page 678): the
// block numbers start at 0 and go up by one per transfer, and the Last bit
// "is set in the last block of the file transfer and cleared in all other
// blocks": the master's READ requests name the next block and never set
// it, since the outstation says which block is the last.
func TestSpecA_27_5_ReadRequests(t *testing.T) {
	s := &fileStation{t: t, block: 4, data: []byte("0123456789")}
	o := newSpecOutstation(t, s.answer)
	c := specDial(t, o, quiet...)
	var out bytes.Buffer
	if _, err := c.ReadFile(testCtx(t), "f", &out, FileOptions{MaxBlockSize: 4}); err != nil || out.String() != "0123456789" {
		t.Fatalf("ReadFile: %q %v", out.String(), err)
	}
	block := uint32(0)
	for _, f := range o.sent() {
		if f.f.Function != app.FuncRead {
			continue
		}
		// C? 01 46 05 5B 01 size(2) handle(4) block(4)
		raw := f.raw
		if len(raw) != 16 || raw[2] != 70 || raw[3] != 5 {
			t.Fatalf("READ % x", raw)
		}
		got := uint32(raw[12]) | uint32(raw[13])<<8 | uint32(raw[14])<<16 | uint32(raw[15])<<24
		if got != block {
			t.Fatalf("READ of block field %#08x, want %d with the Last bit clear", got, block)
		}
		block++
	}
	if block != 3 {
		t.Fatalf("%d READ requests", block)
	}
}

// TestSpec5_3_8_Rule13_ReadErrorAborts: clause 5.3.8 Rule 13 (p. 120): an
// outstation that detects an error in a read request closes the file and
// makes the handle invalid. The client reports the read's error, a
// *dnp3.FileError, and its abort of the transfer accepts the
// INVALID_HANDLE that follows (the client part of OBJECTS2-2).
func TestSpec5_3_8_Rule13_ReadErrorAborts(t *testing.T) {
	s := &fileStation{t: t, block: 4, data: []byte("0123456789"), readStatus: app.FileFatal}
	o := newSpecOutstation(t, s.answer)
	c := specDial(t, o, quiet...)
	var out bytes.Buffer
	n, err := c.ReadFile(testCtx(t), "f", &out, FileOptions{})
	var fe *dnp3.FileError
	if !errors.As(err, &fe) || fe.Status != app.FileFatal || fe.Op != "read" || n != 4 {
		t.Fatalf("ReadFile with a failed block: %d %v", n, err)
	}
	reqs := o.requests()
	if reqs[len(reqs)-1] != app.FuncAbortFile {
		t.Fatalf("requests %v", reqs)
	}
	// The client is usable afterwards.
	if _, err := c.Read(testCtx(t), app.ClassHeaders(1)...); err == nil {
		t.Fatal("READ of class 1 answered by the file station")
	}
}

// levelRow is a row of IEEE 1815-2012 Tables 14-2 to 14-4 for an object the
// master shall parse in responses at subset level 1, 2 or 3.
type levelRow struct {
	g, v  uint8
	level int
	quals []app.Qualifier
	meas  bool // a measurement: Measurements reports it
}

// levelValue is a value of gv for the subset level tests.
func levelValue(gv app.GroupVariation) app.Value {
	ts := app.Timestamp(1767225600123)
	switch gv.Group() {
	case 1, 2, 10:
		t := app.Timestamp(0)
		if gv == app.G2V2 || gv == app.G2V3 {
			t = ts
		}
		return app.Binary{Value: true, Flags: app.FlagOnline, Time: t}
	case 20, 21, 22, 23:
		return app.Counter{Value: 7, Flags: app.FlagOnline}
	case 30, 32, 40:
		return app.Analog{Value: 7, Flags: app.FlagOnline}
	case 50:
		return app.AbsoluteTime{Time: ts}
	case 51:
		return app.CTO{Time: ts}
	case 52:
		return app.TimeDelay{Delay: 3 * time.Second}
	case 80:
		return app.Binary{Value: true}
	}
	return nil
}

// TestSubsetLevelResponses: IEEE 1815-2012 clause 14.7.2 (printed pages
// 427-428) and Tables 14-2 (L1, pp. 398-400), 14-3 (L2, pp. 401-405) and
// 14-4 (L3, pp. 406-412): a master of a level shall parse every object of
// the tables' response columns with every qualifier listed for it. Each
// row goes through the client's receive path as a RESPONSE and as an
// UNSOLICITED_RESPONSE (clause 4.6.6 Rule 2, p. 91: masters parse static
// data there too); the measurements reach the Result and the Handler, and
// each unsolicited response is confirmed with its SEQ and UNS (clause 4.3
// Rule 18, p. 39). Qualifiers: S start-stop 0x00 and 0x01, E index-prefixed
// 0x17 and 0x28, C count 0x07.
func TestSubsetLevelResponses(t *testing.T) {
	S := []app.Qualifier{app.Qual1ByteStartStop, app.Qual2ByteStartStop}
	E := []app.Qualifier{app.Qual1ByteIndexCount, app.Qual2ByteIndexCount}
	C := []app.Qualifier{app.Qual1ByteCount}
	rows := []levelRow{
		{1, 1, 1, S, true}, {1, 2, 1, S, true},
		{2, 1, 1, E, true}, {2, 2, 1, E, true}, {2, 3, 1, E, true},
		{10, 2, 1, S, true},
		{20, 1, 1, S, true}, {20, 2, 1, S, true}, {20, 5, 1, S, true}, {20, 6, 1, S, true},
		{21, 1, 2, S, true}, {21, 2, 2, S, true}, {21, 9, 2, S, true}, {21, 10, 2, S, true},
		{22, 1, 1, E, true}, {22, 2, 1, E, true},
		{23, 1, 3, E, true}, {23, 2, 3, E, true},
		{30, 1, 1, S, true}, {30, 2, 1, S, true}, {30, 3, 1, S, true}, {30, 4, 1, S, true},
		{32, 1, 1, E, true}, {32, 2, 1, E, true},
		{40, 1, 3, S, true}, {40, 2, 1, S, true},
		{50, 1, 3, C, false},
		{51, 1, 1, C, false}, {51, 2, 1, C, false},
		{52, 1, 1, C, false}, {52, 2, 1, C, false},
		{80, 1, 3, S, false},
	}
	var mu sync.Mutex
	var next []byte // the objects of the next response
	o := newSpecOutstation(t, func(req specFrag) [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return [][]byte{frag(app.SingleControl(req.f.Control.Seq), app.FuncResponse, 0, next)}
	})
	rec := newMeasRecorder()
	c := specDial(t, o, append(quiet, WithHandler(rec))...)
	var seq uint8
	confirms, measurements, cases := 0, 0, 0
	for _, r := range rows {
		gv := app.GV(r.g, r.v)
		for _, q := range r.quals {
			name := fmt.Sprintf("L%d %s q=%#02x", r.level, gv, uint8(q))
			var hs []app.Header
			if gv == app.G2V3 {
				hs = append(hs, app.Counted(app.G51V1, app.CTO{Time: 1767225600000}))
			}
			n := 2
			if q.IsCount() || r.g == 80 {
				n = 1
			}
			objs := make([]app.Object, n)
			for i := range objs {
				objs[i] = app.Object{Index: uint32(i + 1), Value: levelValue(gv)}
			}
			hs = append(hs, app.Header{GV: gv, Qualifier: q, Objects: objs})
			b, err := (&app.Fragment{Function: app.FuncResponse, Headers: hs}).Encode()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			objects := b[4:]
			cases++

			// RESPONSE.
			mu.Lock()
			next = objects
			mu.Unlock()
			res, err := c.Read(testCtx(t), app.ClassHeaders(0)...)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got := res.Headers()
			if h := got[len(got)-1]; h.GV != gv || h.Qualifier != q || len(h.Objects) != n {
				t.Fatalf("%s: response header %s", name, &h)
			}
			if r.meas {
				ms := res.Measurements()
				if len(ms) != n {
					t.Fatalf("%s: %d measurements, want %d", name, len(ms), n)
				}
				for i, m := range ms {
					if m.GV != gv || m.Index != uint32(i+1) || m.Event != gv.IsEvent() || !reflect.DeepEqual(m.Value, levelValue(gv)) {
						t.Fatalf("%s: measurement %+v, want %+v", name, m, levelValue(gv))
					}
				}
			}

			// UNSOLICITED_RESPONSE.
			seq = app.NextSeq(seq)
			o.push(t, uns(true, true, true, seq, 0, objects))
			confirms++
			cs := o.waitConfirms(t, confirms)
			if last := cs[len(cs)-1]; last.Seq != seq || !last.UNS {
				t.Fatalf("%s: confirmation %s of unsolicited response seq %d", name, last, seq)
			}
			if r.meas {
				measurements += n
				ms := rec.wait(t, measurements)
				for i, m := range ms[measurements-n:] {
					if m.GV != gv || m.Index != uint32(i+1) || !reflect.DeepEqual(m.Value, levelValue(gv)) {
						t.Fatalf("%s: unsolicited measurement %+v", name, m)
					}
				}
			}
		}
	}
	if cases != 59 { // 27 rows with two qualifiers, 5 with one
		t.Fatalf("%d cases, want 59", cases)
	}
}
