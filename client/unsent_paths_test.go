package client

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
)

// TestEchoOfUnsentRequest: echoStatuses checks a request it is handed
// against the echo, also one that could not have been sent. An analog
// output echo of a value that is not an analog output, and a SELECT echo
// to be compared octet for octet with a request that does not encode,
// are protocol errors, not a panic or a success.
func TestEchoOfUnsentRequest(t *testing.T) {
	ao := app.AnalogOutput{Value: 1}
	crob := app.CROB{Op: app.OpLatchOn, Count: 1}
	// Index 300 does not fit the one-octet index of qualifier 0x17.
	unencodable := app.Header{GV: app.G12V1, Qualifier: app.Qual1ByteIndexCount, Count: 1,
		Objects: []app.Object{{Index: 300, Value: crob}}}
	for _, tc := range []struct {
		name  string
		req   app.Header
		echo  app.Header
		exact bool
		want  string
	}{
		{"analog output echo of a CROB", app.Indexed(app.G41V1, app.Object{Index: 1, Value: crob}),
			app.Indexed(app.G41V1, app.Object{Index: 1, Value: ao}), false, "differs from the request"},
		{"exact echo of a request that does not encode", unencodable,
			app.Indexed(app.G12V1, app.Object{Index: 300, Value: crob}), true, "control echo:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &Result{Fragments: []*app.Fragment{{Function: app.FuncResponse, Headers: []app.Header{tc.echo}}}}
			_, err := echoStatuses([]app.Header{tc.req}, res, tc.exact)
			if !errors.Is(err, dnp3.ErrProtocol) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want ErrProtocol with %q", err, tc.want)
			}
		})
	}
}

// TestFirstFailureTruncated: the statuses of a truncated response end
// before the controls of the request (IEEE 1815-2012 clause 4.4.4.3 Rule
// 6); firstFailure reports the first control that failed among them, and
// none when every one of them succeeded.
func TestFirstFailureTruncated(t *testing.T) {
	req := []app.Header{
		app.Indexed(app.G12V1, app.Object{Index: 1, Value: app.CROB{}}, app.Object{Index: 2, Value: app.CROB{}}),
		app.Indexed(app.G41V1, app.Object{Index: 7, Value: app.AnalogOutput{}}),
	}
	if err := firstFailure(req, []app.CommandStatus{app.StatusSuccess}); err != nil {
		t.Fatalf("one success: %v", err)
	}
	err := firstFailure(req, []app.CommandStatus{app.StatusSuccess, app.StatusSuccess, app.StatusNotSupported})
	var ce *dnp3.CommandError
	if !errors.As(err, &ce) || ce.GV != app.G41V1 || ce.Index != 7 || ce.Status != app.StatusNotSupported {
		t.Fatalf("err %v, want the CommandError of g41v1 index 7", err)
	}
}

// TestConfirmUnencodable: a confirmation that does not encode is not
// sent, and not kept as the last confirmation an outstation may challenge.
func TestConfirmUnencodable(t *testing.T) {
	var log syncBuffer
	c, err := New("127.0.0.1:1", quiet(WithLogger(dnp3.NewSlogLogger(
		slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	f := &app.Fragment{Control: app.SingleControl(3), Function: app.FuncConfirm, Headers: []app.Header{
		{GV: app.G12V1, Qualifier: app.Qual1ByteIndexCount, Count: 1, Objects: []app.Object{{Index: 300, Value: app.CROB{}}}}}}
	c.sendConfirm(closedSession(t), f)
	c.mu.Lock()
	kept := c.auth.lastConfirm
	c.mu.Unlock()
	if kept != nil {
		t.Errorf("kept % x", kept)
	}
	if !strings.Contains(log.String(), "confirmation not sent") {
		t.Errorf("log %q", log.String())
	}
}
