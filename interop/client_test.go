//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
)

// The go-dnp3 master against each reference outstation.

func dialRef(t *testing.T, s *refServer, opts ...client.Option) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, s.addr, append([]client.Option{
		client.WithAddresses(1, link.Address(s.adapter.fixture(t).Outstation.Address)),
		client.WithResponseTimeout(5 * time.Second),
		client.WithAutoIntegrity(false),
	}, opts...)...)
	if err != nil {
		t.Fatalf("dial %s: %v", s.adapter.name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func tctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

// valueOf renders a measurement value the way the contract's object
// documents do.
func valueOf(v app.Value) any {
	switch x := v.(type) {
	case app.Binary:
		return x.Value
	case app.DoubleBitBinary:
		return float64(x.Value)
	case app.Counter:
		return float64(x.Value)
	case app.Analog:
		return x.Value
	case app.OctetString:
		return hex.EncodeToString(x.Data)
	default:
		return fmt.Sprint(v)
	}
}

func TestClientIntegrityPoll(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			s := startServer(t, a)
			c := dialRef(t, s)
			res, err := c.IntegrityPoll(tctx(t))
			if err != nil {
				t.Fatal(err)
			}
			want := a.fixture(t).expectedStatic()
			got := map[string]any{}
			for _, m := range res.Measurements() {
				if !m.Event {
					got[fmt.Sprintf("%s/%d", m.GV, m.Index)] = valueOf(m.Value)
				}
			}
			for k, v := range want {
				if g, ok := got[k]; !ok {
					t.Errorf("%s missing from the integrity poll", k)
				} else if fmt.Sprint(g) != fmt.Sprint(v) {
					t.Errorf("%s = %v, fixture %v", k, g, v)
				}
			}
			for k := range got {
				if _, ok := want[k]; !ok {
					t.Errorf("%s reported but not in the fixture", k)
				}
			}
			if !res.IIN.Has(app.IINDeviceRestart) {
				t.Errorf("first response without DEVICE_RESTART: %s", res.IIN)
			}
		})
	}
}

func TestClientReadRanges(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			s := startServer(t, a)
			c := dialRef(t, s)
			res, err := c.Read(tctx(t), app.IndexRange(app.G30V0, 0, 1), app.IndexRange(app.G1V1, 0, 4))
			if err != nil {
				t.Fatal(err)
			}
			n30, n1 := 0, 0
			for _, m := range res.Measurements() {
				switch m.GV.Group() {
				case 30:
					n30++
				case 1:
					n1++
					// Packed, except points whose quality is not plain
					// ONLINE: every reference reports those with flags.
					b := m.Value.(app.Binary)
					if m.GV != app.G1V1 && (m.GV != app.G1V2 || b.Flags == app.FlagOnline) {
						t.Errorf("asked for g1v1, index %d (flags %s) came as %s", m.Index, b.Flags, m.GV)
					}
				}
			}
			if n30 != 2 || n1 != 5 {
				t.Fatalf("read ranges: %d analog, %d binary", n30, n1)
			}
		})
	}
}

func TestClientControls(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			s := startServer(t, a)
			c := dialRef(t, s)
			ctx := tctx(t)

			// Direct operate binary output 0, which drives binary input 1.
			st, err := c.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0))
			if err != nil || st[0] != app.StatusSuccess {
				t.Fatalf("direct operate: %v %v", st, err)
			}
			s.waitEvent(t, "command", func(e event) bool { return e["event"] == "command" && e["function"] == "direct-operate" })
			res, err := c.Read(ctx, app.AllObjects(app.G10V0), app.IndexRange(app.G1V0, 1, 1))
			if err != nil {
				t.Fatal(err)
			}
			on := map[string]bool{}
			for _, m := range res.Measurements() {
				on[fmt.Sprintf("g%d/%d", m.GV.Group(), m.Index)] = m.Value.(app.Binary).Value
			}
			if !on["g10/0"] || !on["g1/1"] {
				t.Errorf("binary output 0 and its target binary input 1 after LATCH_ON: %v", on)
			}
			// Select-before-operate on output 1, which requires it.
			if _, err := c.Operate(ctx, client.SelectBeforeOperate, client.CROB(1, app.OpLatchOn, 0, 0)); err != nil {
				t.Fatalf("SBO: %v", err)
			}
			// Output 1 refuses direct operate.
			_, err = c.Operate(ctx, client.DirectOperate, client.CROB(1, app.OpLatchOff, 0, 0))
			if !refused(err, app.StatusNotSupported) {
				t.Errorf("direct operate of a select-required output: %v", err)
			}
			// Set-points: in range, and out of range.
			if _, err := c.Operate(ctx, client.DirectOperate, client.SetPoint(0, 1234)); err != nil {
				t.Errorf("set-point: %v", err)
			}
			if _, err := c.Operate(ctx, client.SelectBeforeOperate, client.Command{Index: 1, Value: app.AnalogOutput{Value: 12.5}, GV: app.G41V3}); err != nil {
				t.Errorf("float set-point: %v", err)
			}
			_, err = c.Operate(ctx, client.SelectBeforeOperate, client.Command{Index: 1, Value: app.AnalogOutput{Value: 500}, GV: app.G41V3})
			if !refused(err, app.StatusOutOfRange) {
				t.Errorf("out of range: %v", err)
			}
			// A point that does not exist.
			if _, err := c.Operate(ctx, client.DirectOperate, client.CROB(9, app.OpLatchOn, 0, 0)); !refused(err, app.StatusNotSupported) {
				t.Errorf("missing point: %v", err)
			}
		})
	}
}

// refused reports whether err is the refusal of a control with status,
// either by the echo or by a request error (both P0 outstations set
// PARAMETER_ERROR together with NOT_SUPPORTED).
func refused(err error, status app.CommandStatus) bool {
	var ce *dnp3.CommandError
	if errors.As(err, &ce) {
		return ce.Status == status
	}
	var ie *dnp3.IINError
	return errors.As(err, &ie)
}

func TestClientEvents(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			s := startServer(t, a)
			c := dialRef(t, s)
			ctx := tctx(t)
			if _, err := c.IntegrityPoll(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
				t.Fatal(err)
			}
			res, err := c.EventPoll(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			groups := map[uint8]bool{}
			for _, m := range res.Measurements() {
				if m.Event {
					groups[m.GV.Group()] = true
				}
			}
			if !groups[11] || !groups[2] {
				t.Fatalf("events after a control: %v", groups)
			}
			// Confirmed: not reported again.
			res, _ = c.EventPoll(ctx, 1)
			if len(res.Measurements()) != 0 {
				t.Fatalf("events reported twice")
			}
		})
	}
}

func TestClientUnsolicited(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "unsolicited")
			s := startServer(t, a)
			got := make(chan client.Measurement, 16)
			h := client.HandlerFunc(func(info client.ResponseInfo, ms []client.Measurement) {
				if info.Unsolicited {
					for _, m := range ms {
						got <- m
					}
				}
			})
			c := dialRef(t, s, client.WithHandler(h),
				client.WithStartup(client.Startup{DisableUnsolicited: true, Integrity: true, EnableUnsolicited: []int{1, 2, 3}}))
			if _, err := c.Operate(tctx(t), client.DirectOperate, client.SetPoint(0, 77)); err != nil {
				t.Fatal(err)
			}
			deadline := time.After(10 * time.Second)
			for seen := map[uint8]bool{}; !seen[42] || !seen[32]; {
				select {
				case m := <-got:
					seen[m.GV.Group()] = true
				case <-deadline:
					t.Fatalf("unsolicited events: %v", seen)
				}
			}
		})
	}
}

func TestClientTimeSync(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		for _, p := range []struct {
			name string
			proc client.TimeSync
			feat string
		}{{"lan", client.TimeSyncLAN, "timeSyncLan"}, {"non-lan", client.TimeSyncNonLAN, "timeSyncNonLan"}} {
			t.Run(a.name+"/"+p.name, func(t *testing.T) {
				a.need(t, p.feat)
				s := startServer(t, a)
				c := dialRef(t, s)
				res, err := c.Read(tctx(t), app.AllObjects(app.G80V1))
				if err != nil && !isIINErr(err) {
					t.Fatal(err)
				}
				if res != nil && !res.IIN.Has(app.IINNeedTime) {
					t.Fatalf("NEED_TIME not set: %s", res.IIN)
				}
				if err := c.SyncTime(tctx(t), p.proc); err != nil {
					t.Fatal(err)
				}
				e := s.waitEvent(t, "time-sync", func(e event) bool { return e["event"] == "time-sync" })
				ts, err := time.Parse(time.RFC3339Nano, fmt.Sprint(e["time"]))
				if err != nil || time.Since(ts).Abs() > 5*time.Second {
					t.Errorf("written time %v (%v)", e["time"], err)
				}
				res, err = c.Read(tctx(t), app.AllObjects(app.G80V1))
				if err == nil && res.IIN.Has(app.IINNeedTime) {
					t.Errorf("NEED_TIME after synchronization")
				}
			})
		}
	}
}

func isIINErr(err error) bool {
	var ie *dnp3.IINError
	return errors.As(err, &ie)
}

func TestClientRestart(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		for _, cold := range []bool{true, false} {
			name := a.name + "/warm"
			if cold {
				name = a.name + "/cold"
			}
			t.Run(name, func(t *testing.T) {
				// A fresh outstation for each: a restart in progress may
				// refuse the next one (ALREADY_EXECUTING).
				s := startServer(t, a)
				c := dialRef(t, s)
				f := a.fixture(t).Outstation
				want, restart := f.WarmRestartDelayMs, c.WarmRestart
				if cold {
					want, restart = f.ColdRestartDelayMs, c.ColdRestart
				}
				d, err := restart(tctx(t))
				if err != nil || want == nil || d != time.Duration(*want)*time.Millisecond {
					t.Errorf("restart: %v %v", d, err)
				}
			})
		}
	}
}

func TestClientFreeze(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			s := startServer(t, a)
			c := dialRef(t, s)
			ctx := tctx(t)
			if err := c.Freeze(ctx, true, false, app.AllObjects(app.G20V0)); err != nil {
				t.Fatalf("freeze and clear: %v", err)
			}
			res, err := c.Read(ctx, app.AllObjects(app.G21V0), app.AllObjects(app.G20V0))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range res.Measurements() {
				v := m.Value.(app.Counter).Value
				switch {
				case m.GV.Group() == 20 && v != 0 && (m.Index != 2 || !knownBug(t, a, "freeze-clear-without-frozen")):
					t.Errorf("counter %d not cleared: %d", m.Index, v)
				case m.GV.Group() == 21 && m.Index == 0 && v != 123456:
					t.Errorf("frozen counter 0 = %d", v)
				}
			}
		})
	}
}

func TestClientAssignClass(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "assignClassServer")
			s := startServer(t, a)
			c := dialRef(t, s)
			if err := c.AssignClass(tctx(t), 3, app.IndexRange(app.G40V0, 0, 0)); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Operate(tctx(t), client.DirectOperate, client.SetPoint(0, 5)); err != nil {
				t.Fatal(err)
			}
			res, err := c.EventPoll(tctx(t), 3)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, m := range res.Measurements() {
				found = found || (m.GV.Group() == 42 && m.Index == 0)
			}
			if !found {
				t.Fatal("analog output event not in class 3 after ASSIGN_CLASS")
			}
		})
	}
}
