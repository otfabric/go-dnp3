//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/server"
)

// The requests without a response (DIRECT OPERATE NO ACK and the _NR
// freezes), and reads of all objects of a group.

// eventually waits for cond, the effect of a request that has no response.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: no effect within 5s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestClientNoAck(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "directOperateNoAckServer", "freezeNoAckServer")
			s := startServer(t, a)
			c := dialRef(t, s)
			ctx := tctx(t)
			if _, err := c.Operate(ctx, client.DirectOperateNoAck, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
				t.Fatalf("direct operate no ack: %v", err)
			}
			eventually(t, "DIRECT OPERATE NO ACK of binary output 0", func() bool {
				res, err := c.Read(ctx, app.IndexRange(app.G10V0, 0, 0))
				ms := res.Measurements()
				return err == nil && len(ms) == 1 && ms[0].Value.(app.Binary).Value
			})
			if err := c.Freeze(ctx, true, true, app.AllObjects(app.G20V0)); err != nil {
				t.Fatalf("freeze and clear no ack: %v", err)
			}
			eventually(t, "FREEZE AND CLEAR NO ACK", func() bool {
				res, err := c.Read(ctx, app.AllObjects(app.G20V0))
				if err != nil {
					return false
				}
				for _, m := range res.Measurements() {
					if m.Value.(app.Counter).Value != 0 && (m.Index != 2 || !knownBug(t, a, "freeze-clear-without-frozen")) {
						return false
					}
				}
				return true
			})
		})
	}
}

func TestServerNoAck(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			caps := a.capabilities(t).Features
			if !caps["directOperateNoAckClient"] && !caps["freezeNoAckClient"] {
				t.Skipf("%s sends neither DIRECT OPERATE NO ACK nor the _NR freezes", a.name)
			}
			st, port := serveFixture(t, a)
			db := st.srv.Database()
			if caps["directOperateNoAckClient"] {
				if r := runClient(t, a, port, "operate", "--type", "g12v1", "--index", "0", "--code", "LATCH_ON", "--mode", "direct-no-ack"); !r.OK {
					t.Fatalf("direct operate no ack: %s", r.errorCode())
				}
				eventually(t, "DIRECT OPERATE NO ACK", func() bool {
					v, _ := db.Get(server.BinaryOutput, 0)
					return v.(app.Binary).Value
				})
			}
			if caps["freezeNoAckClient"] {
				if r := runClient(t, a, port, "freeze", "--clear", "--no-ack"); !r.OK {
					t.Fatalf("freeze and clear no ack: %s", r.errorCode())
				}
				eventually(t, "FREEZE AND CLEAR NO ACK", func() bool {
					v, _ := db.Get(server.Counter, 0)
					return v.(app.Counter).Value == 0
				})
			}
		})
	}
}

func TestServerReadAllObjects(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "readAllObjectsClient")
			_, port := serveFixture(t, a)
			for _, g := range []struct {
				group string
				want  int
			}{{"1", len(a.fixture(t).BinaryInputs)}, {"30", len(a.fixture(t).AnalogInputs)}, {"110", len(a.fixture(t).OctetStrings)}} {
				r := runClient(t, a, port, "read", "--group", g.group, "--variation", "0")
				if !r.OK || len(r.Objects) != g.want {
					t.Errorf("read of all objects of group %s: ok=%v %s, %d objects, fixture %d", g.group, r.OK, r.errorCode(), len(r.Objects), g.want)
				}
			}
		})
	}
}
