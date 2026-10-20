//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

// Contract 1.2: the extended fixture (frozen analogs, command events, time
// and interval), the dual end point, security statistic events and the
// dnp3py fixture.

const extendedFixture = "/fixtures/extended/fixture.json"

func TestClientExtended(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "commandEventsServer")
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", extendedFixture}})
			c := dialRef(t, s)
			ctx := tctx(t)

			res, err := c.Read(ctx, app.IndexRange(app.G31V0, 0, 1))
			if err != nil {
				t.Fatalf("read of the frozen analog inputs: %v", err)
			}
			got := map[uint32]client.Measurement{}
			for _, m := range res.Measurements() {
				got[m.Index] = m
			}
			if v := got[0].Value.(app.Analog); got[0].GV != app.G31V1 || v.Value != 1500 {
				t.Errorf("frozen analog input 0: %s %+v", got[0].GV, v)
			}
			if v := got[1].Value.(app.Analog); got[1].GV != app.G31V7 || v.Value != 49.5 || v.Flags != app.FlagOnline|app.FlagOverRange {
				t.Errorf("frozen analog input 1: %s %+v", got[1].GV, v)
			}

			res, err = c.Read(ctx, app.IndexRange(app.G50V4, 0, 0))
			if err != nil {
				t.Fatalf("read of the time and interval: %v", err)
			}
			want := fixtureInterval{Time: "2026-01-01T00:00:00.000Z", Interval: 15, Units: 3}.value()
			if hs := res.Headers(); len(hs) != 1 || hs[0].GV != app.G50V4 || hs[0].Objects[0].Value.(app.AbsoluteTime) != want {
				t.Errorf("time and interval: %v", hs)
			}

			if _, err := c.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0), client.SetPoint(0, 42)); err != nil {
				t.Fatalf("controls: %v", err)
			}
			res, err = c.EventPoll(ctx, 2)
			if err != nil {
				t.Fatal(err)
			}
			var seen []string
			for _, m := range res.Measurements() {
				switch v := m.Value.(type) {
				case app.BinaryCommandEvent:
					if m.GV != app.G13V2 || !v.Value || v.Status != app.StatusSuccess {
						t.Errorf("binary command event %s %+v", m.GV, v)
					}
					seen = append(seen, "g13")
				case app.AnalogCommandEvent:
					if m.GV != app.G43V3 || v.Value != 42 || v.Status != app.StatusSuccess {
						t.Errorf("analog command event %s %+v", m.GV, v)
					}
					seen = append(seen, "g43")
				}
			}
			if len(seen) != 2 {
				t.Errorf("command events in class 2: %v", seen)
			}
		})
	}
}

func TestServerExtended(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			caps := a.capabilities(t).Features
			if !caps["commandEventsClient"] && !caps["frozenAnalogInputsClient"] && !caps["timeAndIntervalClient"] {
				t.Skipf("%s's master decodes none of the extended types", a.name)
			}
			st, err := newStation(a.fixtureNamed(t, "extended"))
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

			if caps["frozenAnalogInputsClient"] {
				r := runClient(t, a, port, "read", "--group", "31", "--variation", "0", "--start", "0", "--stop", "1")
				got := map[string]string{}
				for _, o := range r.Objects {
					got[key(o)] = fmt.Sprint(o.Value)
				}
				if !r.OK || got["g31v1/0"] != "1500" || got["g31v7/1"] != "49.5" {
					t.Errorf("frozen analog inputs: ok=%v %s %v", r.OK, r.errorCode(), got)
				}
			}
			if caps["timeAndIntervalClient"] {
				r := runClient(t, a, port, "read", "--group", "50", "--variation", "4", "--start", "0", "--stop", "0")
				if !r.OK || len(r.Objects) != 1 || fmt.Sprint(r.Objects[0].Value) != "15" || r.Objects[0].Units == nil || *r.Objects[0].Units != 3 ||
					r.Objects[0].Time != "2026-01-01T00:00:00.000Z" {
					t.Errorf("time and interval: ok=%v %s %+v", r.OK, r.errorCode(), r.Objects)
				}
			}
			if caps["commandEventsClient"] {
				if r := runClient(t, a, port, "operate", "--type", "g12v1", "--index", "0", "--code", "LATCH_ON"); !r.OK {
					t.Fatalf("operate: %s", r.errorCode())
				}
				if r := runClient(t, a, port, "operate", "--type", "g41v1", "--index", "0", "--value", "42"); !r.OK {
					t.Fatalf("set-point: %s", r.errorCode())
				}
				r := runClient(t, a, port, "event-poll", "--classes", "2")
				var seen []string
				for _, o := range r.Objects {
					switch o.Group {
					case 13:
						if o.Value != true || o.Status != "SUCCESS" || o.Variation != 2 {
							t.Errorf("binary command event %+v", o)
						}
						seen = append(seen, "g13")
					case 43:
						if fmt.Sprint(o.Value) != "42" || o.Status != "SUCCESS" || o.Variation != 3 {
							t.Errorf("analog command event %+v", o)
						}
						seen = append(seen, "g43")
					}
				}
				if len(seen) != 2 {
					t.Errorf("command events in class 2: ok=%v %s %v", r.OK, r.errorCode(), r.Objects)
				}
			}
		})
	}
}

// TestClientDualEndPoint: the reference outstation connects to go-dnp3's
// master, over TCP and TLS.
func TestClientDualEndPoint(t *testing.T) {
	requireDocker(t)
	p := testPKI(t)
	for _, a := range adapters(t) {
		for _, withTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls=%v", a.name, withTLS), func(t *testing.T) {
				a.needServer(t, "dualEndpointServer")
				l, err := net.Listen("tcp", "0.0.0.0:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = l.Close() })
				ln := net.Listener(l)
				args := []string{"--connect", net.JoinHostPort("host.docker.internal", strconv.Itoa(l.Addr().(*net.TCPAddr).Port))}
				docker := []string{"--add-host=host.docker.internal:host-gateway"}
				if withTLS {
					a.need(t, "tls")
					ln = tls.NewListener(l, p.serverTLS())
					// The dialling outstation is the TLS client.
					args = append(args, "--tls-cert", "/pki/client.pem", "--tls-key", "/pki/client.key", "--tls-ca", "/pki/ca.pem")
					docker = append(docker, p.mount()...)
				}
				startServerSpec(t, a, serverSpec{port: "-", docker: docker, args: args})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				c, err := client.Dial(ctx, "outstation", client.WithStream(client.Accept(ln)), client.WithAutoIntegrity(false),
					client.WithAddresses(1, link.Address(a.fixture(t).Outstation.Address)), client.WithResponseTimeout(5*time.Second))
				if err != nil {
					t.Fatalf("waiting for the outstation's connection: %v", err)
				}
				defer func() { _ = c.Close() }()
				res, err := c.IntegrityPoll(ctx)
				if err != nil {
					t.Fatal(err)
				}
				checkStatic(t, a.fixture(t), staticCount(res))
			})
		}
	}
}

// TestServerDualEndPoint: go-dnp3's outstation connects to the reference
// master, which listens, over TCP and TLS.
func TestServerDualEndPoint(t *testing.T) {
	requireDocker(t)
	p := testPKI(t)
	for _, a := range adapters(t) {
		for _, withTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls=%v", a.name, withTLS), func(t *testing.T) {
				a.need(t, "dualEndpointClient")
				var opts []server.Option
				argv := []string{"integrity-poll", "--listen", "--port", "20000", "--connect-timeout-ms", "20000"}
				port := freePort(t)
				docker := []string{"-p", fmt.Sprintf("127.0.0.1:%d:20000", port)}
				if withTLS {
					a.need(t, "dualEndpointClientTls")
					// The outstation is the TLS client of the listening master.
					cfg := p.clientTLS(p.client)
					cfg.ServerName = ""
					opts = append(opts, server.WithTLS(cfg))
					argv = append(argv, "--tls", "--tls-cert", "/pki/server.pem", "--tls-key", "/pki/server.key", "--tls-ca", "/pki/ca.pem")
					docker = append(docker, p.mount()...)
				}
				st, err := newStation(a.fixture(t), opts...)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				go func() {
					_ = st.srv.DialAndServe(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), server.Redial{MinDelay: 100 * time.Millisecond, MaxDelay: time.Second})
				}()
				t.Cleanup(func() { cancel(); _ = st.srv.Close() })
				r := runClientSpec(t, a, docker, argv)
				if !r.OK {
					t.Fatalf("integrity poll over the outstation's connection: %s", r.errorCode())
				}
				if want := len(a.fixture(t).expectedStatic()); len(r.Objects) != want {
					t.Errorf("%d objects, fixture %d", len(r.Objects), want)
				}
			})
		}
	}
}

// TestClientSecurityStatisticEvents: the reference outstation raises g122
// events in the class and at the threshold it is given.
func TestClientSecurityStatisticEvents(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.needServer(t, "securityStatisticsServer")
			s := startServer(t, a, "--sa-update-key", hex.EncodeToString(updateKey), "--sa-statistics-class", "2", "--sa-statistics-threshold", "1")
			c := dialRef(t, s, client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: updateKey}))
			if _, err := c.Operate(tctx(t), client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
				t.Fatal(err)
			}
			res, err := c.EventPoll(tctx(t), 2)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, h := range res.Headers() {
				if h.GV.Group() == 122 {
					n += len(h.Objects)
				}
			}
			if n == 0 {
				t.Fatalf("no security statistic events in class 2: %v", res.Headers())
			}
		})
	}
}

// TestServerSecurityStatistics: the reference master reads go-dnp3's
// statistics and their events.
func TestServerSecurityStatistics(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "securityStatisticsClient")
			st, err := newStation(a.fixture(t), server.WithSecureAuthentication(server.SecureAuth{
				User: secauth.User{Number: 1, UpdateKey: updateKey}, StatisticsClass: 3, StatisticsThreshold: 1}))
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
			key := hex.EncodeToString(updateKey)
			r := runClient(t, a, port, "read", "--group", "121", "--variation", "1", "--start", "0", "--stop", "17", "--sa-update-key", key)
			if !r.OK || len(r.Objects) != int(secauth.NumStatistics) {
				t.Fatalf("read of the statistics: ok=%v %s, %d objects", r.OK, r.errorCode(), len(r.Objects))
			}
			for _, o := range r.Objects {
				if o.Association == nil || *o.Association != float64(a.fixture(t).Outstation.MasterAddress) {
					t.Errorf("statistic %d: association %v", o.Index, o.Association)
				}
			}
			r = runClient(t, a, port, "event-poll", "--classes", "3", "--sa-update-key", key)
			n := 0
			for _, o := range r.Objects {
				if o.Group == 122 {
					n++
				}
			}
			if !r.OK || n == 0 {
				t.Fatalf("statistic events in class 3: ok=%v %s, %v", r.OK, r.errorCode(), r.Objects)
			}
		})
	}
}

// TestClientDnp3pyFixture: the dnp3py fixture, which every outstation
// serves, dnp3py's included.
func TestClientDnp3pyFixture(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			f := a.fixtureNamed(t, "dnp3py")
			s := startServerSpec(t, a, serverSpec{args: []string{"--fixture", "/fixtures/dnp3py/fixture.json"}})
			c := dialRef(t, s)
			res, err := c.IntegrityPoll(tctx(t))
			if err != nil {
				t.Fatal(err)
			}
			want := f.expectedStatic()
			got := map[string]any{}
			for _, m := range res.Measurements() {
				if !m.Event {
					got[fmt.Sprintf("%s/%d", m.GV, m.Index)] = valueOf(m.Value)
				}
			}
			for k, v := range want {
				if g, ok := got[k]; !ok {
					t.Errorf("%s missing", k)
				} else if fmt.Sprint(g) != fmt.Sprint(v) {
					t.Errorf("%s = %v, fixture %v", k, g, v)
				}
			}
			// Binary output 0 drives binary input 1.
			if _, err := c.Operate(tctx(t), client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
				t.Fatalf("direct operate: %v", err)
			}
			res, err = c.Read(tctx(t), app.AllObjects(app.G1V0))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range res.Measurements() {
				if m.Index == 1 && !m.Value.(app.Binary).Value {
					t.Error("binary input 1 did not follow binary output 0")
				}
			}
		})
	}
}
