//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/secauth"
	"github.com/otfabric/go-dnp3/server"
)

// Secure Authentication version 5, challenge-reply mode, with session
// keys changed under the update key, both directions.

// authRequests counts the AUTHENTICATE_REQ requests of a master: key
// status requests and key changes.
type authRequests struct {
	dnp3.NopMetrics
	ok, failed atomic.Int64
}

func (m *authRequests) OnRequest(net.Addr, uint16, app.FunctionCode)           {}
func (m *authRequests) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) {}
func (m *authRequests) OnRequestDone(_ net.Addr, _ uint16, fc app.FunctionCode, _ time.Duration, err error) {
	if fc != app.FuncAuthRequest {
		return
	}
	if err != nil {
		m.failed.Add(1)
	} else {
		m.ok.Add(1)
	}
}

var (
	updateKey      = []byte("go-dnp3 interop!") // 16 octets: AES-128 key wrap
	wrongUpdateKey = bytes.Repeat([]byte{0x5A}, 16)
)

func TestClientSecureAuth(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "secureAuthentication")
			s := startServer(t, a, "--sa-update-key", hex.EncodeToString(updateKey))
			operate := func(c *client.Client, code app.OpType) {
				t.Helper()
				st, err := c.Operate(tctx(t), client.DirectOperate, client.CROB(0, code, 0, 0))
				if err != nil || st[0] != app.StatusSuccess {
					t.Fatalf("challenged direct operate: %v %v", st, err)
				}
			}
			user := client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: updateKey})

			// The key change at connect, a challenged control, then the
			// periodic key change: its key status message is the one of
			// an established session, with a MAC value.
			m := &authRequests{}
			c := dialRef(t, s, user, client.WithKeyChangeInterval(time.Second), client.WithMetrics(m))
			operate(c, app.OpLatchOn)
			s.waitEvent(t, "auth", func(e event) bool { return e["event"] == "auth" && e["function"] == float64(app.FuncDirectOperate) })
			deadline := time.Now().Add(5 * time.Second)
			for m.ok.Load() < 4 && m.failed.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if m.failed.Load() != 0 || m.ok.Load() < 4 {
				t.Fatalf("key changes: %d requests answered, %d failed", m.ok.Load(), m.failed.Load())
			}
			operate(c, app.OpLatchOff)
			_ = c.Close()

			// A second connection: both ends drop the session keys when a
			// connection ends, so this is a first key change again.
			c = dialRef(t, s, user)
			operate(c, app.OpLatchOn)
			_ = c.Close()

			// Another update key: the key change fails.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			wc, err := client.Dial(ctx, s.addr, client.WithAutoIntegrity(false), client.WithResponseTimeout(2*time.Second),
				client.WithAddresses(1, link.Address(a.fixture(t).Outstation.Address)),
				client.WithSecureAuthentication(secauth.User{Number: 1, UpdateKey: wrongUpdateKey}))
			if err == nil {
				_, err = wc.Operate(ctx, client.DirectOperate, client.CROB(0, app.OpLatchOn, 0, 0))
				_ = wc.Close()
			}
			if err == nil {
				t.Fatal("control with a wrong update key succeeded")
			}
		})
	}
}

func TestServerSecureAuth(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "secureAuthentication")
			st, err := newStation(a.fixture(t), server.WithSecureAuthentication(server.SecureAuth{
				User: secauth.User{Number: 1, UpdateKey: updateKey}}))
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

			op := func(key []byte, code string) *result {
				return runClient(t, a, port, "operate", "--type", "g12v1", "--index", "0", "--code", code,
					"--sa-update-key", hex.EncodeToString(key))
			}
			// Two master runs, each with its own key change.
			for _, code := range []string{"LATCH_ON", "LATCH_OFF"} {
				if r := op(updateKey, code); !r.OK || r.CommandStatus == nil || *r.CommandStatus != "SUCCESS" {
					t.Fatalf("challenged %s: %s", code, r.errorCode())
				}
			}
			if r := op(wrongUpdateKey, "LATCH_ON"); r.OK {
				t.Fatal("go-dnp3 executed a control of a master with a wrong update key")
			}
			// Without secure authentication the control is not executed.
			if r := runClient(t, a, port, "operate", "--type", "g12v1", "--index", "0", "--code", "LATCH_ON"); r.OK {
				t.Fatal("go-dnp3 executed a control without authentication")
			}
		})
	}
}
