// SPDX-License-Identifier: MIT

package client

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// selectAnswer answers SELECT with the octets mutate makes of the
// request's octets after its function code, and every other request with
// an exact echo.
func selectAnswer(iin app.IIN, mutate func(objects []byte) []byte) func(req specFrag) [][]byte {
	return func(req specFrag) [][]byte {
		if req.f.Function != app.FuncSelect {
			return [][]byte{echo(req, 0)}
		}
		objects := mutate(bytes.Clone(req.raw[2:]))
		return [][]byte{frag(app.SingleControl(req.f.Control.Seq), app.FuncResponse, iin, objects)}
	}
}

// The CROB of CROB(0, app.OpLatchOn, 100, 100) after the function code:
// the object header (g12v1, qualifier 0x17, one object), the index, the
// control code, the count, the on and off times and the status.
//
//	0c 01 17 01 | 00 | 03 01 64 00 00 00 64 00 00 00 00
const (
	crobOnTime = 7  // first octet of the on time
	crobStatus = 15 // the status octet
)

// TestSpec4_4_4_3_Rule8_SelectEchoComparedOctetForOctet: IEEE 1815-2012
// clause 4.4.4.3 Rule 8 (printed page 51): "A master shall compare all of
// the octets following the two IIN octets in the select response with all
// of the octets following the function code octet in the request. If the
// octets do not match exactly [...] the master shall not issue the
// matching operate command". A response that carries the same objects
// encoded differently (qualifier 0x28 where the request had 0x17) does not
// match either (MASTER-1).
func TestSpec4_4_4_3_Rule8_SelectEchoComparedOctetForOctet(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cmds   []Command
		mutate func(b []byte) []byte
	}{
		{"other on time", []Command{CROB(0, app.OpLatchOn, 100, 100)}, func(b []byte) []byte {
			b[crobOnTime]++
			return b
		}},
		{"qualifier 0x28 for the same index", []Command{CROB(0, app.OpLatchOn, 100, 100)}, func(b []byte) []byte {
			out := []byte{0x0c, 0x01, 0x28, 0x01, 0x00, 0x00, 0x00}
			return append(out, b[5:]...)
		}},
		{"an extra header", []Command{CROB(0, app.OpLatchOn, 100, 100)}, func(b []byte) []byte {
			extra := bytes.Clone(b)
			extra[4] = 1 // index 1
			return append(b, extra...)
		}},
		{"an object missing, the others successful", []Command{CROB(0, app.OpLatchOn, 100, 100), CROB(1, app.OpLatchOn, 100, 100)}, func(b []byte) []byte {
			// 0c 01 17 02 | 00 crob | 01 crob: keep the first, count 1.
			out := bytes.Clone(b[:4+1+11])
			out[3] = 1
			return out
		}},
		{"another set-point value", []Command{{Index: 3, Value: app.AnalogOutput{Value: 1.5}, GV: app.G41V3}}, func(b []byte) []byte {
			// 29 03 17 01 | 03 | float32 | status
			b[6] ^= 0x01
			return b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newSpecOutstation(t, selectAnswer(0, tc.mutate))
			c := specDial(t, o, quiet...)
			_, err := c.Operate(testCtx(t), SelectBeforeOperate, tc.cmds...)
			if !errors.Is(err, dnp3.ErrProtocol) {
				t.Fatalf("mismatched select response: %v", err)
			}
			if got := o.requests(); !slices.Equal(got, []app.FunctionCode{app.FuncSelect}) {
				t.Fatalf("requests %v: an OPERATE followed a mismatched select response", got)
			}
		})
	}

	// The exact echo is operated.
	o := newSpecOutstation(t, selectAnswer(0, func(b []byte) []byte { return b }))
	c := specDial(t, o, quiet...)
	st, err := c.Operate(testCtx(t), SelectBeforeOperate, CROB(0, app.OpLatchOn, 100, 100), SetPoint(2, 7))
	if err != nil || !slices.Equal(st, []app.CommandStatus{app.StatusSuccess, app.StatusSuccess}) {
		t.Fatalf("exact echo: %v %v", st, err)
	}
	if got := o.requests(); !slices.Equal(got, []app.FunctionCode{app.FuncSelect, app.FuncOperate}) {
		t.Fatalf("requests %v", got)
	}
}

// TestSpec4_4_4_3_Rule8_SelectErrorsStopOperate: clause 4.4.4.3 Rule 8
// (p. 51): the master shall not issue the operate command when "the status
// code returned in any object is non-zero" or IIN2.0, 2.1, 2.2 or 2.4 is
// set, even when the response repeats the request.
func TestSpec4_4_4_3_Rule8_SelectErrorsStopOperate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		iin    app.IIN
		status app.CommandStatus
	}{
		{"IIN2.0 NO_FUNC_CODE_SUPPORT", app.IINNoFuncCodeSupport, 0},
		{"IIN2.1 OBJECT_UNKNOWN", app.IINObjectUnknown, 0},
		{"IIN2.2 PARAMETER_ERROR", app.IINParameterError, 0},
		{"IIN2.4 ALREADY_EXECUTING", app.IINAlreadyExecuting, 0},
		{"status NOT_SUPPORTED", 0, app.StatusNotSupported},
		{"status NON_PARTICIPATING", 0, app.StatusNonParticipating},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newSpecOutstation(t, selectAnswer(tc.iin, func(b []byte) []byte {
				b[crobStatus] = byte(tc.status)
				return b
			}))
			c := specDial(t, o, quiet...)
			_, err := c.Operate(testCtx(t), SelectBeforeOperate, CROB(0, app.OpLatchOn, 100, 100))
			var ie *dnp3.IINError
			var ce *dnp3.CommandError
			switch {
			case tc.iin != 0 && errors.As(err, &ie) && ie.IIN.Has(tc.iin):
			case tc.iin == 0 && errors.As(err, &ce) && ce.Status == tc.status && ce.Index == 0:
			default:
				t.Fatalf("select response with %s: %v", tc.name, err)
			}
			if got := o.requests(); !slices.Equal(got, []app.FunctionCode{app.FuncSelect}) {
				t.Fatalf("requests %v: an OPERATE followed a failed select", got)
			}
		})
	}
}

// TestSpec4_4_4_3_Rule6_TruncatedResponse: clause 4.4.4.3 Rule 6 (p. 50):
// the response of an outstation to a control request that failed for a
// point "shall include [...] Only objects for all of the points up to and
// including the first unsuccessful point. This is called a truncated
// response." The master reports the status of that point, a
// *dnp3.CommandError, and sends no OPERATE (Rule 8); a response that
// leaves out objects otherwise is not a valid echo (MASTER-15).
func TestSpec4_4_4_3_Rule6_TruncatedResponse(t *testing.T) {
	three := []Command{CROB(0, app.OpLatchOn, 100, 100), CROB(1, app.OpLatchOn, 100, 100), CROB(2, app.OpLatchOn, 100, 100)}
	// truncate keeps the first n CROBs of the request, with statuses.
	truncate := func(statuses ...app.CommandStatus) func(b []byte) []byte {
		return func(b []byte) []byte {
			out := bytes.Clone(b[:4])
			out[3] = byte(len(statuses))
			for i, s := range statuses {
				obj := bytes.Clone(b[4+12*i : 4+12*(i+1)])
				obj[11] = byte(s)
				out = append(out, obj...)
			}
			return out
		}
	}
	for _, mode := range []CommandMode{DirectOperate, SelectBeforeOperate} {
		o := newSpecOutstation(t, func(req specFrag) [][]byte {
			objects := truncate(app.StatusSuccess, app.StatusNotSupported)(bytes.Clone(req.raw[2:]))
			return [][]byte{frag(app.SingleControl(req.f.Control.Seq), app.FuncResponse, 0, objects)}
		})
		c := specDial(t, o, quiet...)
		st, err := c.Operate(testCtx(t), mode, three...)
		var ce *dnp3.CommandError
		if !errors.As(err, &ce) || ce.Index != 1 || ce.Status != app.StatusNotSupported {
			t.Fatalf("mode %d: truncated response: %v", mode, err)
		}
		if !slices.Equal(st, []app.CommandStatus{app.StatusSuccess, app.StatusNotSupported}) {
			t.Fatalf("mode %d: statuses %v", mode, st)
		}
		if got := o.requests(); len(got) != 1 {
			t.Fatalf("mode %d: requests %v", mode, got)
		}
	}

	// Not a truncated response: a missing object with every status 0, or
	// a failed point that is not the last one returned.
	for _, statuses := range [][]app.CommandStatus{
		{app.StatusSuccess, app.StatusSuccess},
		{app.StatusNotSupported, app.StatusSuccess},
	} {
		o := newSpecOutstation(t, func(req specFrag) [][]byte {
			objects := truncate(statuses...)(bytes.Clone(req.raw[2:]))
			return [][]byte{frag(app.SingleControl(req.f.Control.Seq), app.FuncResponse, 0, objects)}
		})
		c := specDial(t, o, quiet...)
		if _, err := c.Operate(testCtx(t), DirectOperate, three...); !errors.Is(err, dnp3.ErrProtocol) {
			t.Fatalf("statuses %v of 3 controls: %v", statuses, err)
		}
	}
}

// TestSpec4_4_4_3_Rule9_SelectOperateSequence: clause 4.4.4.1 (pp. 48-49):
// the master "issues an operate command with the identical object set of
// headers and objects that it sent in the select message", and clause
// 4.4.4.3 Rule 4 with Table 4-9 (p. 50) accepts it only with the sequence
// number N+1 of a select with N.
func TestSpec4_4_4_3_Rule9_SelectOperateSequence(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{echo(req, 0)} })
	c := specDial(t, o, quiet...)
	if _, err := c.Operate(testCtx(t), SelectBeforeOperate, CROB(4, app.OpPulseOn, 250, 0), SetPoint(1, 2.5)); err != nil {
		t.Fatal(err)
	}
	sent := o.sent()
	if len(sent) != 2 || sent[0].f.Function != app.FuncSelect || sent[1].f.Function != app.FuncOperate {
		t.Fatalf("requests %v", o.requests())
	}
	if n := sent[0].f.Control.Seq; sent[1].f.Control.Seq != app.NextSeq(n) {
		t.Fatalf("SELECT seq %d, OPERATE seq %d", n, sent[1].f.Control.Seq)
	}
	if !bytes.Equal(sent[0].raw[2:], sent[1].raw[2:]) {
		t.Fatalf("OPERATE differs from the SELECT:\n % x\n % x", sent[1].raw[2:], sent[0].raw[2:])
	}
}

// TestSpec4_4_4_3_Rule9_SelectNotRetried: clause 4.4.4.3 Rule 9 (p. 51):
// "The master shall not retry the select–operate sequence in its
// entirety." Controls are never repeated under WithRetry: a select that
// is not answered is sent once, and so is a direct operate.
func TestSpec4_4_4_3_Rule9_SelectNotRetried(t *testing.T) {
	o := newSpecOutstation(t, func(specFrag) [][]byte { return nil })
	c := specDial(t, o, append(quiet, WithResponseTimeout(100*time.Millisecond),
		WithRetry(Retry{Attempts: 3, Backoff: 10 * time.Millisecond}))...)
	if _, err := c.Operate(testCtx(t), SelectBeforeOperate, CROB(0, app.OpLatchOn, 0, 0)); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("unanswered select: %v", err)
	}
	if _, err := c.Operate(testCtx(t), DirectOperate, CROB(0, app.OpLatchOn, 0, 0)); !errors.Is(err, dnp3.ErrTimeout) {
		t.Fatalf("unanswered direct operate: %v", err)
	}
	if got := o.requests(); !slices.Equal(got, []app.FunctionCode{app.FuncSelect, app.FuncDirectOperate}) {
		t.Fatalf("requests %v", got)
	}
}

// TestSpecA_8_1_2_2_RequestFields: Annex A.8.1.2.2 (printed page 506):
// the queue bit of a CROB is obsolete and "The master shall always set
// this bit to 0"; the status of a CROB (A.8.1.2.2, p. 507) and of an
// analog output block (A.20.1.2.2, p. 615) is 0 in a request, or 126
// NON_PARTICIPATING, which Table 11-7 (p. 330) defines for requests. The
// client refuses other values with dnp3.ErrInvalidOption and sends
// nothing (OBJECTS1-15).
func TestSpecA_8_1_2_2_RequestFields(t *testing.T) {
	o := newSpecOutstation(t, func(req specFrag) [][]byte { return [][]byte{echo(req, 0)} })
	c := specDial(t, o, quiet...)
	for _, cmd := range []Command{
		{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1, Queue: true}},
		{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1, Status: app.StatusTimeout}},
		{Index: 0, Value: app.AnalogOutput{Value: 1, Status: app.StatusNotSupported}},
	} {
		for _, mode := range []CommandMode{SelectBeforeOperate, DirectOperate, DirectOperateNoAck} {
			if _, err := c.Operate(testCtx(t), mode, cmd); !errors.Is(err, dnp3.ErrInvalidOption) {
				t.Fatalf("%+v mode %d: %v", cmd.Value, mode, err)
			}
		}
	}
	if got := o.requests(); len(got) != 0 {
		t.Fatalf("requests %v", got)
	}
	// NON_PARTICIPATING is sent; what the outstation answers for it is
	// not the subject here.
	nonParticipating := Command{Index: 0, Value: app.CROB{Op: app.OpNul, Status: app.StatusNonParticipating}}
	if _, err := c.Operate(testCtx(t), DirectOperate, nonParticipating, CROB(1, app.OpLatchOn, 0, 0)); errors.Is(err, dnp3.ErrInvalidOption) {
		t.Fatalf("NON_PARTICIPATING refused: %v", err)
	}
	sent := o.sent()
	if len(sent) != 1 || sent[0].f.Headers[0].Objects[0].Value.(app.CROB).Status != app.StatusNonParticipating {
		t.Fatalf("requests %v", o.requests())
	}
}
