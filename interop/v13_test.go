//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/server"
)

// Contract 1.3: device attributes, several controls in one request, freeze
// at time and analog freeze, deadbands, file append and authentication,
// event buffer overflow, link confirms and keep-alive, broadcast,
// management functions and several outstations behind one port.

func fixturePath(name string) string { return "/fixtures/" + name + "/fixture.json" }

// serveNamed serves the named fixture of a with go-dnp3's outstation.
func serveNamed(t *testing.T, a adapter, name string, opts ...server.Option) (*station, int) {
	t.Helper()
	st, err := newStation(a.fixtureNamed(t, name), opts...)
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

// attrValue renders a device attribute's type and value.
func attrValue(a app.Attribute) string {
	switch a.Type {
	case app.AttrUnsignedInt:
		v, err := a.Uint()
		return fmt.Sprintf("uint %d %v", v, err)
	case app.AttrSignedInt:
		v, err := a.Int()
		return fmt.Sprintf("int %d %v", v, err)
	default:
		return fmt.Sprintf("%s %q", a.Type, a.Data)
	}
}

func status(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestClientAttributes(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "deviceAttributesServer")
			f := a.fixtureNamed(t, "attributes")
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", fixturePath("attributes")}})
			c := dialRef(t, s)
			ctx := tctx(t)
			got, err := c.ReadAttributeSet(ctx, 1, app.AttrAllAttributes)
			if err != nil {
				t.Fatal(err)
			}
			for _, fa := range f.DeviceAttributes {
				// Compared by value: an integer may be sent in 1, 2 or 4 octets.
				if g, want := attrValue(got[fa.Variation]), attrValue(fa.attribute()); g != want {
					t.Errorf("set 1 variation %d: %s, fixture %s", fa.Variation, g, want)
				}
			}
			if err := c.WriteAttributeSet(ctx, 1, 10, app.StringAttribute("written by go-dnp3")); err != nil {
				t.Fatalf("write of a writable attribute: %v", err)
			}
			if got, _ := c.ReadAttributeSet(ctx, 1, 10); string(got[10].Data) != "written by go-dnp3" {
				t.Errorf("after the write: %v", got)
			}
			s.waitEvent(t, "attribute-write", func(e event) bool { return e["event"] == "attribute-write" })
			if err := c.WriteAttributeSet(ctx, 1, 1, app.StringAttribute("x")); err == nil {
				t.Error("a read-only attribute was written")
			}
		})
	}
}

func TestServerAttributes(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "deviceAttributesClient")
			f := a.fixtureNamed(t, "attributes")
			_, port := serveNamed(t, a, "attributes")
			r := runClient(t, a, port, "attribute-read", "--set", "1")
			if !r.OK {
				t.Fatalf("attribute-read: %s", r.errorCode())
			}
			got := map[int]resultAttr{}
			for _, at := range r.Attributes {
				got[at.Variation] = at
			}
			for _, fa := range f.DeviceAttributes {
				var want any
				_ = json.Unmarshal(fa.Value, &want)
				if g := got[int(fa.Variation)]; g.Type != fa.Type || fmt.Sprint(g.Value) != fmt.Sprint(want) {
					t.Errorf("variation %d: %+v, fixture %s %v", fa.Variation, g, fa.Type, want)
				}
			}
			if r := runClient(t, a, port, "attribute-write", "--set", "1", "--variation", "10", "--text", "written"); !r.OK {
				t.Fatalf("attribute-write: %s", r.errorCode())
			}
			r = runClient(t, a, port, "attribute-read", "--set", "1", "--variation", "10")
			if len(r.Attributes) != 1 || r.Attributes[0].Value != "written" {
				t.Errorf("after the write: %+v", r.Attributes)
			}
			if r := runClient(t, a, port, "attribute-write", "--set", "1", "--variation", "1", "--text", "x"); r.OK {
				t.Error("go-dnp3 let a read-only attribute be written")
			}
		})
	}
}

func TestClientMultipleControls(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "maxControlsServer")
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", fixturePath("controls")}})
			c := dialRef(t, s)
			ctx := tctx(t)
			st, err := c.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0), client.SetPoint(0, 5))
			if err != nil || len(st) != 2 || st[0] != app.StatusSuccess || st[1] != app.StatusSuccess {
				t.Fatalf("two controls: %v %v", st, err)
			}
			// The fixture allows two: the third is refused, the first two
			// are carried out.
			st, _ = c.Operate(ctx, client.DirectOperate, client.CROB(1, app.OpLatchOn, 0, 0), client.CROB(2, app.OpLatchOn, 0, 0), client.SetPoint(1, 7))
			if len(st) != 3 || st[0] != app.StatusSuccess || st[1] != app.StatusSuccess || st[2] != app.StatusTooManyObjects {
				t.Fatalf("three controls of a limit of two: %v", st)
			}
			res, err := c.Read(ctx, app.AllObjects(app.G10V0))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range res.Measurements() {
				if m.Index <= 2 && !m.Value.(app.Binary).Value {
					t.Errorf("binary output %d not on", m.Index)
				}
			}
		})
	}
}

func TestServerMultipleControls(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "multipleControlsClient")
			st, port := serveNamed(t, a, "controls")
			r := runClient(t, a, port, "operate-multi", "--controls", "g12v1:0:LATCH_ON,g41v1:0:5")
			if !r.OK {
				t.Fatalf("two controls: %s %v", r.errorCode(), r.CommandStatuses)
			}
			r = runClient(t, a, port, "operate-multi", "--controls", "g12v1:1:LATCH_ON,g12v1:2:LATCH_ON,g41v1:1:7")
			if r.OK || status(r.CommandStatus) != "TOO_MANY_OPS" {
				t.Errorf("three controls of a limit of two: ok=%v %s %s", r.OK, r.errorCode(), status(r.CommandStatus))
			}
			if r.CommandStatuses != nil && (len(r.CommandStatuses) != 3 || status(r.CommandStatuses[0]) != "SUCCESS" || status(r.CommandStatuses[2]) != "TOO_MANY_OPS") {
				t.Errorf("statuses %v", r.CommandStatuses)
			}
			db := st.srv.Database()
			for i := range uint32(3) {
				if v, _ := db.Get(server.BinaryOutput, i); !v.(app.Binary).Value {
					t.Errorf("binary output %d not on", i)
				}
			}
			if v, _ := db.Get(server.AnalogOutput, 1); v.(app.Analog).Value == 7 {
				t.Error("the refused set-point was carried out")
			}
		})
	}
}

func TestClientFreezeAtTime(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "freezeAtTimeServer")
			s := startServer(t, a)
			c := dialRef(t, s)
			ctx := tctx(t)
			before, err := c.Read(ctx, app.IndexRange(app.G21V0, 1, 1))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.FreezeAtTime(ctx, time.Now().Add(time.Second), 0, app.AllObjects(app.G20V0)); err != nil {
				t.Fatalf("freeze at time: %v", err)
			}
			want := a.fixture(t).Counters[1].number()
			if fmt.Sprint(valueOf(before.Measurements()[0].Value)) == fmt.Sprint(want) {
				t.Skip("frozen counter 1 already holds the counter's value")
			}
			eventually(t, "the freeze at its time", func() bool {
				res, err := c.Read(ctx, app.IndexRange(app.G21V0, 1, 1))
				return err == nil && len(res.Measurements()) == 1 && fmt.Sprint(valueOf(res.Measurements()[0].Value)) == fmt.Sprint(want)
			})
		})
	}
}

func TestClientAnalogFreeze(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "analogFreezeServer")
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", extendedFixture}})
			c := dialRef(t, s)
			ctx := tctx(t)
			if _, err := c.Operate(ctx, client.DirectOperate, client.SetPoint(0, 321)); err != nil {
				t.Fatal(err)
			}
			if err := c.Freeze(ctx, false, false, app.IndexRange(app.G30V0, 0, 0)); err != nil {
				t.Fatalf("analog freeze: %v", err)
			}
			eventually(t, "frozen analog input 0", func() bool {
				res, err := c.Read(ctx, app.IndexRange(app.G31V0, 0, 0))
				return err == nil && len(res.Measurements()) == 1 && res.Measurements()[0].Value.(app.Analog).Value == 321
			})
		})
	}
}

func TestServerFreezeAtTimeAndAnalogFreeze(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			caps := a.capabilities(t).Features
			if !caps["freezeAtTimeClient"] && !caps["analogFreezeClient"] {
				t.Skipf("%s sends neither", a.name)
			}
			if caps["freezeAtTimeClient"] {
				st, port := serveFixture(t, a)
				db := st.srv.Database()
				_ = db.UpdateCounter(0, app.Counter{Value: 777, Flags: app.FlagOnline})
				if r := runClient(t, a, port, "freeze", "--at", "+1000"); !r.OK {
					t.Fatalf("freeze at time: %s", r.errorCode())
				}
				eventually(t, "the freeze at its time", func() bool {
					v, _ := db.Get(server.FrozenCounter, 0)
					return v.(app.Counter).Value == 777
				})
			}
			if caps["analogFreezeClient"] {
				st, port := serveNamed(t, a, "extended")
				db := st.srv.Database()
				_ = db.UpdateAnalogInput(0, app.Analog{Value: 654, Flags: app.FlagOnline})
				if r := runClient(t, a, port, "freeze", "--group", "30"); !r.OK {
					t.Fatalf("analog freeze: %s", r.errorCode())
				}
				eventually(t, "frozen analog input 0", func() bool {
					v, _ := db.Get(server.FrozenAnalogInput, 0)
					return v.(app.Analog).Value == 654
				})
			}
		})
	}
}

func TestClientDeadbands(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "deadbandWriteServer")
			s := startServer(t, a)
			c := dialRef(t, s)
			ctx := tctx(t)
			if _, err := c.Write(ctx, app.Indexed(app.G34V3, app.Object{Index: 0, Value: app.AnalogDeadband{Value: 2.5}})); err != nil {
				t.Fatalf("deadband write: %v", err)
			}
			if !a.capabilities(t).Features["deadbandReadServer"] {
				return
			}
			res, err := c.Read(ctx, app.IndexRange(app.G34V3, 0, 0))
			if err != nil {
				t.Fatal(err)
			}
			if hs := res.Headers(); len(hs) != 1 || hs[0].Objects[0].Value.(app.AnalogDeadband).Value != 2.5 {
				t.Errorf("deadband read back: %v", hs)
			}
		})
	}
}

func TestServerDeadbands(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "deadbandWriteClient")
			_, port := serveFixture(t, a)
			if r := runClient(t, a, port, "deadband-write", "--deadbands", "0:2.5,1:40"); !r.OK {
				t.Fatalf("deadband write: %s", r.errorCode())
			}
			if !a.capabilities(t).Features["deadbandReadClient"] {
				return
			}
			r := runClient(t, a, port, "read", "--group", "34", "--variation", "3", "--start", "0", "--stop", "1")
			got := map[int]string{}
			for _, o := range r.Objects {
				got[o.Index] = fmt.Sprint(o.Value)
			}
			if !r.OK || got[0] != "2.5" || got[1] != "40" {
				t.Errorf("deadbands read back: ok=%v %s %v", r.OK, r.errorCode(), got)
			}
		})
	}
}

func TestClientFileAppendAndAuth(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "fileAuthServer", "fileAppendServer")
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", filesFixture, "--file-user", "operator", "--file-password", "secret"}})
			c := dialRef(t, s)
			ctx := tctx(t)
			var buf bytes.Buffer
			if _, err := c.ReadFile(ctx, "/readme.txt", &buf, client.FileOptions{}); fileStatus(err) != app.FilePermissionDenied {
				t.Errorf("read without authentication: %v", err)
			}
			if _, err := c.AuthenticateFile(ctx, "operator", "wrong"); err == nil {
				t.Error("wrong password accepted")
			}
			key, err := c.AuthenticateFile(ctx, "operator", "secret")
			if err != nil || key == 0 {
				t.Fatalf("authenticate: %d %v", key, err)
			}
			want := fixtureFiles(a.fixtureNamed(t, "files"))["/readme.txt"]
			tail := []byte("appended by go-dnp3\n")
			if _, err := c.WriteFile(ctx, "/readme.txt", bytes.NewReader(tail), uint32(len(tail)), client.FileOptions{AuthKey: key, Append: true}); err != nil {
				t.Fatalf("append: %v", err)
			}
			key, _ = c.AuthenticateFile(ctx, "operator", "secret")
			buf.Reset()
			if _, err := c.ReadFile(ctx, "/readme.txt", &buf, client.FileOptions{AuthKey: key}); err != nil || !bytes.Equal(buf.Bytes(), append(append([]byte(nil), want...), tail...)) {
				t.Errorf("after the append: %q %v", buf.String(), err)
			}
		})
	}
}

func TestServerFileAppendAndAuth(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			caps := a.capabilities(t).Features
			if !caps["fileAppendClient"] && !caps["fileAuthClient"] {
				t.Skipf("%s has neither", a.name)
			}
			st, port := serveNamed(t, a, "files")
			want := fixtureFiles(a.fixtureNamed(t, "files"))["/readme.txt"]
			if caps["fileAppendClient"] {
				tail := []byte("appended\n")
				if r := runClient(t, a, port, "file-put", "--name", "/readme.txt", "--append", "--content", hex.EncodeToString(tail)); !r.OK {
					t.Fatalf("append: %s", r.errorCode())
				}
				if b, _ := st.files.get("/readme.txt"); !bytes.Equal(b, append(append([]byte(nil), want...), tail...)) {
					t.Errorf("after the append: %q", b)
				}
			}
			if caps["fileAuthClient"] {
				st.files.requireAuth("operator", "secret")
				if r := runClient(t, a, port, "file-info", "--name", "/readme.txt"); r.OK && r.File != nil {
					// GET_FILE_INFO is not an open: it needs no key.
					_ = r
				}
				if r := runClient(t, a, port, "file-get", "--name", "/readme.txt"); r.OK {
					t.Error("file-get without authentication succeeded")
				}
				if r := runClient(t, a, port, "file-get", "--name", "/readme.txt", "--file-user", "operator", "--file-password", "secret"); !r.OK {
					t.Errorf("file-get with authentication: %s", r.errorCode())
				}
				if r := runClient(t, a, port, "file-authenticate", "--file-user", "operator", "--file-password", "wrong"); r.OK {
					t.Error("a wrong password authenticated")
				}
			}
		})
	}
}

func TestClientEventBufferOverflow(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "eventBufferServer")
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", fixturePath("events")}})
			c := dialRef(t, s)
			ctx := tctx(t)
			// Each set-point moves analog input 0 and makes an event: more
			// than the buffer of three holds (dnp3py's class buffer holds
			// three times it), so that some are lost.
			for i := range 12 {
				if _, err := c.Operate(ctx, client.DirectOperate, client.SetPoint(0, float64(10*(i+1)))); err != nil {
					t.Fatal(err)
				}
			}
			res, err := c.Read(ctx, app.ClassHeaders(0)...)
			if err != nil {
				t.Fatal(err)
			}
			if !res.IIN.Has(app.IINEventBufferOverflow) {
				t.Fatalf("no EVENT_BUFFER_OVERFLOW after six events into a buffer of three: %s", res.IIN)
			}
		})
	}
}

func TestServerEventBufferOverflow(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			st, port := serveNamed(t, a, "events")
			for i := range 6 {
				_ = st.srv.Database().UpdateAnalogInput(0, app.Analog{Value: float64(10 * (i + 1)), Flags: app.FlagOnline})
			}
			r := runClient(t, a, port, "integrity-poll")
			if !slices.Contains(r.IIN, "EVENT_BUFFER_OVERFLOW") {
				t.Fatalf("IIN after six events into a buffer of three: %v", r.IIN)
			}
		})
	}
}

// linkStatusCounter counts the REQUEST_LINK_STATUS frames an outstation
// receives.
type linkStatusCounter struct {
	dnp3.NopMetrics
	n atomic.Int64
}

func (m *linkStatusCounter) OnFrameReceived(_ net.Addr, f *link.Frame, _ int) {
	if f.Function == link.PrimaryRequestLinkStatus {
		m.n.Add(1)
	}
}

func TestClientLinkLayer(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			caps := a.capabilities(t)
			confirms := caps.Features["linkConfirmsServer"]
			status := caps.Features["linkStatusEventServer"]
			if !confirms && !status {
				t.Skipf("%s's outstation has neither", a.name)
			}
			var args []string
			if confirms {
				args = append(args, "--link-confirms")
			}
			s := startServer(t, a, args...)
			c := dialRef(t, s, client.WithLink(client.Link{Confirmed: confirms, KeepAlive: 300 * time.Millisecond}))
			res, err := c.IntegrityPoll(tctx(t))
			if err != nil {
				t.Fatalf("integrity poll with link confirms=%v: %v", confirms, err)
			}
			checkStatic(t, a.fixture(t), staticCount(res))
			if status {
				s.waitEvent(t, "link-status", func(e event) bool { return e["event"] == "link-status" })
			}
		})
	}
}

func TestServerLinkLayer(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			caps := a.capabilities(t).Features
			if !caps["linkConfirmsClient"] && !caps["keepAliveClient"] {
				t.Skipf("%s's master has neither", a.name)
			}
			m := &linkStatusCounter{}
			opts := []server.Option{server.WithMetrics(m)}
			if caps["linkConfirmsClient"] {
				opts = append(opts, server.WithLink(server.Link{Confirmed: true}))
			}
			st, err := newStation(a.fixture(t), opts...)
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = st.srv.Serve(l) }()
			t.Cleanup(func() { _ = st.srv.Close() })
			port := l.Addr().(*net.TCPAddr).Port
			if caps["linkConfirmsClient"] {
				if r := runClient(t, a, port, "integrity-poll", "--link-confirms"); !r.OK || len(r.Objects) != len(a.fixture(t).expectedStatic()) {
					t.Errorf("integrity poll with link confirms: ok=%v %s, %d objects", r.OK, r.errorCode(), len(r.Objects))
				}
			}
			if caps["keepAliveClient"] {
				if r := runClient(t, a, port, "monitor", "--duration-ms", "1500", "--keep-alive-ms", "200"); !r.OK {
					t.Fatalf("monitor with keep-alives: %s", r.errorCode())
				}
				if m.n.Load() == 0 {
					t.Error("no REQUEST_LINK_STATUS arrived")
				}
			}
		})
	}
}

func TestClientBroadcast(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "broadcastServer")
			s := startServer(t, a)
			c := dialRef(t, s)
			ctx := tctx(t)
			crob := app.Indexed(app.G12V1, app.Object{Index: 0, Value: app.CROB{Op: app.OpLatchOn, Count: 1}})
			if err := c.Broadcast(ctx, link.BroadcastNoConfirm, app.FuncDirectOperateNoAck, crob); err != nil {
				t.Fatal(err)
			}
			eventually(t, "the broadcast control", func() bool {
				res, err := c.Read(ctx, app.IndexRange(app.G10V0, 0, 0))
				return err == nil && len(res.Measurements()) == 1 && res.Measurements()[0].Value.(app.Binary).Value
			})
			if a.capabilities(t).Features["broadcastEventServer"] {
				s.waitEvent(t, "broadcast", func(e event) bool {
					return e["event"] == "broadcast" && e["function"] == float64(app.FuncDirectOperateNoAck)
				})
			}
		})
	}
}

func TestServerBroadcast(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "broadcastClient")
			st, port := serveFixture(t, a)
			if r := runClient(t, a, port, "operate", "--type", "g12v1", "--index", "0", "--code", "LATCH_ON", "--mode", "direct-no-ack", "--broadcast"); !r.OK {
				t.Fatalf("broadcast: %s", r.errorCode())
			}
			eventually(t, "the broadcast control", func() bool {
				v, _ := st.srv.Database().Get(server.BinaryOutput, 0)
				return v.(app.Binary).Value
			})
		})
	}
}

var managed = []struct {
	op string
	fc app.FunctionCode
}{
	{"initialize-data", app.FuncInitializeData}, {"initialize-application", app.FuncInitializeApplication},
	{"start-application", app.FuncStartApplication}, {"stop-application", app.FuncStopApplication},
	{"save-configuration", app.FuncSaveConfiguration},
}

func TestClientManagement(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "manageServer")
			s := startServer(t, a)
			c := dialRef(t, s)
			for _, m := range managed {
				var hs []app.Header
				if m.fc == app.FuncInitializeApplication || m.fc == app.FuncStartApplication || m.fc == app.FuncStopApplication {
					hs = []app.Header{app.AllObjects(app.GV(90, 1))}
				}
				if _, err := c.Request(tctx(t), m.fc, hs...); err != nil {
					t.Errorf("%s: %v", m.op, err)
					continue
				}
				s.waitEvent(t, "manage "+m.op, func(e event) bool { return e["event"] == "manage" && e["function"] == float64(m.fc) })
			}
		})
	}
}

func TestServerManagement(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "manageClient")
			st, port := serveFixture(t, a)
			for _, m := range managed {
				if r := runClient(t, a, port, "manage", "--function", m.op); !r.OK {
					t.Errorf("%s: %s", m.op, r.errorCode())
				}
			}
			st.mu.Lock()
			defer st.mu.Unlock()
			if len(st.managed) != len(managed) {
				t.Errorf("functions handled: %v", st.managed)
			}
		})
	}
}

// TestClientSeveralOutstations: one port, several outstations; a master
// for each, and a request to an address nobody has goes unanswered.
func TestClientSeveralOutstations(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "multipleOutstationsServer")
			s := startServer(t, a, "--outstations", "3")
			base := a.fixture(t).Outstation.Address
			for i := range uint16(3) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				// Longer than opendnp3's unsolicited confirm timeout (5 s): its
				// outstation can hold a READ until then when its startup
				// unsolicited response crossed it (INTEROPERABILITY.md).
				c, err := client.Dial(ctx, s.addr, client.WithAddresses(1, link.Address(base+i)), client.WithAutoIntegrity(false),
					client.WithResponseTimeout(12*time.Second))
				if err != nil {
					cancel()
					t.Fatalf("outstation %d: %v", base+i, err)
				}
				res, err := c.IntegrityPoll(ctx)
				if err != nil {
					t.Errorf("outstation %d: %v", base+i, err)
				} else {
					checkStatic(t, a.fixture(t), staticCount(res))
				}
				_ = c.Close()
				cancel()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := client.New(s.addr, client.WithAddresses(1, link.Address(base+3)), client.WithAutoIntegrity(false),
				client.WithResponseTimeout(time.Second), client.WithStartup(client.Startup{}), client.WithAutoClearRestart(false))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if err := c.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := c.IntegrityPoll(ctx); err == nil {
				t.Errorf("outstation %d answered, beyond the three", base+3)
			}
		})
	}
}

// TestServerSeveralOutstations: go-dnp3's outstations at three addresses
// behind one port (server.Group); each reference master reaches each by
// its link address, and an address nobody has goes unanswered.
func TestServerSeveralOutstations(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			f := a.fixture(t)
			base := f.Outstation.Address
			var servers []*server.Server
			for i := range uint16(3) {
				g := *f
				g.Outstation.Address = base + i
				st, err := newStation(&g)
				if err != nil {
					t.Fatal(err)
				}
				// Outstation i tells itself apart by binary input 0.
				_ = st.srv.Database().Update(server.BinaryInput, 0, app.Binary{Value: i == 1, Flags: app.FlagOnline}, server.EventSuppress)
				servers = append(servers, st.srv)
			}
			grp, err := server.NewGroup(servers...)
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = grp.Serve(l) }()
			t.Cleanup(func() { _ = grp.Close() })
			port := l.Addr().(*net.TCPAddr).Port
			for i := range uint16(3) {
				r := runClient(t, a, port, "read", "--group", "1", "--variation", "2", "--start", "0", "--stop", "0", "--remote-addr", fmt.Sprint(base+i))
				if !r.OK || len(r.Objects) != 1 || r.Objects[0].Value != (i == 1) {
					t.Errorf("outstation %d: ok=%v %s %+v", base+i, r.OK, r.errorCode(), r.Objects)
				}
			}
			if r := runClient(t, a, port, "integrity-poll", "--remote-addr", fmt.Sprint(base+3), "--timeout-ms", "1500"); r.OK {
				t.Errorf("outstation %d answered, beyond the three", base+3)
			}
		})
	}
}
