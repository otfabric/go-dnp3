//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Each reference master against go-dnp3's outstation serving the baseline
// fixture.

// serveFixture starts go-dnp3's outstation for a's baseline fixture on a
// port the containers reach as host.docker.internal.
func serveFixture(t *testing.T, a adapter) (*station, int) {
	t.Helper()
	st, err := newStation(a.fixture(t))
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

func key(o resultObj) string { return fmt.Sprintf("g%dv%d/%d", o.Group, o.Variation, o.Index) }

func TestServerIntegrityPoll(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			_, port := serveFixture(t, a)
			r := runClient(t, a, port, "integrity-poll")
			if !r.OK {
				t.Fatalf("integrity poll failed: %s", r.errorCode())
			}
			want := a.fixture(t).expectedStatic()
			got := map[string]any{}
			for _, o := range r.Objects {
				got[key(o)] = o.Value
			}
			for k, v := range want {
				if g, ok := got[k]; !ok {
					t.Errorf("%s missing", k)
				} else if fmt.Sprint(g) != fmt.Sprint(v) {
					t.Errorf("%s = %v, fixture %v", k, g, v)
				}
			}
			if len(got) != len(want) {
				t.Errorf("%d objects, fixture %d", len(got), len(want))
			}
			// Flags as the fixture gives them.
			for _, o := range r.Objects {
				if key(o) == "g1v2/2" && strings.Join(o.Flags, ",") != "ONLINE,LOCAL_FORCED" {
					t.Errorf("binary input 2 flags %v", o.Flags)
				}
				if key(o) == "g30v1/3" && strings.Join(o.Flags, ",") != "OVER_RANGE" {
					t.Errorf("analog input 3 flags %v", o.Flags)
				}
			}
		})
	}
}

func TestServerRead(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			_, port := serveFixture(t, a)
			r := runClient(t, a, port, "read", "--group", "30", "--variation", "0", "--start", "0", "--stop", "2")
			if !r.OK || len(r.Objects) != 3 {
				t.Fatalf("read g30 0..2: %s, %d objects", r.errorCode(), len(r.Objects))
			}
			r = runClient(t, a, port, "read", "--group", "30", "--variation", "5", "--start", "1", "--stop", "1")
			if !r.OK || len(r.Objects) != 1 || r.Objects[0].Variation != 5 || fmt.Sprint(r.Objects[0].Value) != "-1234" {
				t.Fatalf("read g30v5 index 1: %s %+v", r.errorCode(), r.Objects)
			}
		})
	}
}

func TestServerControls(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			_, port := serveFixture(t, a)
			op := func(args ...string) *result { return runClient(t, a, port, "operate", args...) }
			status := func(r *result) string {
				if r.CommandStatus == nil {
					return "<nil>"
				}
				return *r.CommandStatus
			}
			if r := op("--type", "g12v1", "--index", "0", "--code", "LATCH_ON"); !r.OK || status(r) != "SUCCESS" {
				t.Errorf("direct LATCH_ON: %s %s", r.errorCode(), status(r))
			}
			if r := op("--type", "g12v1", "--index", "1", "--code", "LATCH_ON", "--mode", "sbo"); !r.OK {
				t.Errorf("SBO on select-required output: %s %s", r.errorCode(), status(r))
			}
			if r := op("--type", "g12v1", "--index", "1", "--code", "LATCH_OFF"); r.OK || (r.errorCode() != "command-failed" && r.errorCode() != "rejected") {
				t.Errorf("direct operate of a select-required output: %s %s", r.errorCode(), status(r))
			}
			if r := op("--type", "g41v1", "--index", "0", "--value", "1234"); !r.OK {
				t.Errorf("set-point: %s %s", r.errorCode(), status(r))
			}
			if r := op("--type", "g41v3", "--index", "1", "--value", "500", "--mode", "sbo"); r.OK || status(r) != "OUT_OF_RANGE" && r.errorCode() != "rejected" {
				t.Errorf("out of range: %s %s", r.errorCode(), status(r))
			}
			if r := op("--type", "g12v1", "--index", "0", "--code", "PULSE_OFF"); r.OK {
				t.Errorf("unsupported code accepted: %s", status(r))
			}
			// The control's effect: output 0 and its target binary input 1
			// are on, analog input 4 follows analog output 0.
			r := runClient(t, a, port, "integrity-poll")
			got := map[string]any{}
			for _, o := range r.Objects {
				got[fmt.Sprintf("g%d/%d", o.Group, o.Index)] = o.Value
			}
			if got["g10/0"] != true || got["g1/1"] != true || fmt.Sprint(got["g30/4"]) != "1234" || fmt.Sprint(got["g40/0"]) != "1234" {
				t.Errorf("after the controls: %v", got)
			}
		})
	}
}

func TestServerEvents(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			_, port := serveFixture(t, a)
			_ = runClient(t, a, port, "integrity-poll")
			if r := runClient(t, a, port, "operate", "--type", "g12v1", "--index", "0", "--code", "LATCH_ON"); !r.OK {
				t.Fatal(r.errorCode())
			}
			r := runClient(t, a, port, "event-poll", "--classes", "1")
			groups := map[int]bool{}
			for _, o := range r.Objects {
				groups[o.Group] = true
			}
			if !r.OK || !groups[11] || !groups[2] {
				t.Fatalf("event poll: %s %v", r.errorCode(), groups)
			}
			// Confirmed by the master: gone.
			if r := runClient(t, a, port, "event-poll", "--classes", "1"); len(r.Objects) != 0 {
				t.Fatalf("events reported twice: %d", len(r.Objects))
			}
		})
	}
}

func TestServerTimeSyncRestartFreeze(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			// A fresh outstation per procedure: it sets NEED_TIME again, and
			// a master without timeSyncOnDemand synchronizes only then.
			for _, p := range []string{"lan", "non-lan"} {
				st, port := serveFixture(t, a)
				if r := runClient(t, a, port, "time-sync", "--procedure", p); !r.OK {
					t.Errorf("time sync %s: %s", p, r.errorCode())
					continue
				}
				st.mu.Lock()
				n := len(st.times)
				var last time.Time
				if n > 0 {
					last = st.times[n-1]
				}
				st.mu.Unlock()
				if n != 1 || time.Since(last).Abs() > 5*time.Second {
					t.Errorf("time sync %s: time written %d times, last %v", p, n, last)
				}
			}
			_, port := serveFixture(t, a)
			r := runClient(t, a, port, "restart", "--type", "cold")
			if !r.OK {
				t.Errorf("cold restart: %s", r.errorCode())
			} else if r.RestartDelayMs != nil && *r.RestartDelayMs != 5000 {
				t.Errorf("cold restart delay %v", *r.RestartDelayMs)
			}
			if r := runClient(t, a, port, "restart", "--type", "warm"); !r.OK {
				t.Errorf("warm restart: %s", r.errorCode())
			}
			if r := runClient(t, a, port, "freeze", "--clear"); !r.OK {
				t.Fatalf("freeze and clear: %s", r.errorCode())
			}
			r = runClient(t, a, port, "integrity-poll")
			for _, o := range r.Objects {
				k := fmt.Sprintf("g%d/%d", o.Group, o.Index)
				switch {
				case o.Group == 20 && fmt.Sprint(o.Value) != "0":
					t.Errorf("%s not cleared: %v", k, o.Value)
				case k == "g21/0" && fmt.Sprint(o.Value) != "123456":
					t.Errorf("frozen counter 0 = %v", o.Value)
				}
			}
		})
	}
}

func TestServerUnsolicited(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			_, port := serveFixture(t, a)
			if r := runClient(t, a, port, "enable-unsolicited"); !r.OK {
				t.Fatalf("enable unsolicited: %s", r.errorCode())
			}
			// The classes stay enabled on the next connection: a control
			// there raises events that arrive unsolicited on it.
			r := runClient(t, a, port, "operate", "--type", "g41v1", "--index", "0", "--value", "9", "--collect-ms", "2000")
			uns := 0
			for _, o := range r.Objects {
				if o.Unsolicited {
					uns++
				}
			}
			if !r.OK || uns == 0 {
				t.Fatalf("monitor: %s, %d unsolicited objects of %d", r.errorCode(), uns, len(r.Objects))
			}
			if r := runClient(t, a, port, "disable-unsolicited"); !r.OK {
				t.Errorf("disable unsolicited: %s", r.errorCode())
			}
		})
	}
}

func TestServerAssignClass(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "assignClassClient")
			_, port := serveFixture(t, a)
			if r := runClient(t, a, port, "assign-class", "--class", "3", "--group", "40", "--start", "0", "--stop", "0"); !r.OK {
				t.Fatalf("assign class: %s", r.errorCode())
			}
			_ = runClient(t, a, port, "event-poll", "--classes", "1,2,3")
			if r := runClient(t, a, port, "operate", "--type", "g41v1", "--index", "0", "--value", "3"); !r.OK {
				t.Fatal(r.errorCode())
			}
			r := runClient(t, a, port, "event-poll", "--classes", "3")
			found := false
			for _, o := range r.Objects {
				found = found || (o.Group == 42 && o.Index == 0)
			}
			if !found {
				t.Fatalf("analog output event not in class 3: %+v", r.Objects)
			}
		})
	}
}

var _ = strconv.Itoa
