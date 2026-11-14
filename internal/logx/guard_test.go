// SPDX-License-Identifier: MIT

package logx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

// recorded is a structured logger that keeps its entries as text.
func recorded() (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	base := dnp3.NewSlogLogger(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return New(base, "test"), &buf
}

// TestGuardedCalls: Run, Do, Call and Try return what the call returns; a
// call that does not return normally gives a *CallbackError naming it,
// with the value, and is logged at error level with the value and the
// stack: by Run, Do and Call at once, after Try when Report is given its
// Failure.
func TestGuardedCalls(t *testing.T) {
	l, buf := recorded()
	errCall := errors.New("refused")
	if err := Run(l, "f", func() {}); err != nil {
		t.Errorf("Run of a call that returns: %v", err)
	}
	if err := Do(l, "f", func() error { return errCall }); err != errCall {
		t.Errorf("Do of a call that returns an error: %v", err)
	}
	if v, err := Call(l, "f", func() (int, error) { return 7, nil }); v != 7 || err != nil {
		t.Errorf("Call of a call that returns: %d %v", v, err)
	}
	if fail, err := Try("f", func() error { return errCall }); fail != nil || err != errCall {
		t.Errorf("Try of a call that returns an error: %v %v", fail, err)
	}
	l.Report(nil)
	if buf.Len() != 0 {
		t.Fatalf("calls that return were logged:\n%s", buf)
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Run", func() error { return Run(l, "Run callback", func() { panic("value of Run") }) }},
		{"Do", func() error { return Do(l, "Do callback", func() error { panic("value of Do") }) }},
		{"Call", func() error {
			v, err := Call(l, "Call callback", func() (int, error) { panic("value of Call") })
			if v != 0 {
				t.Errorf("Call returned %d, want the zero value", v)
			}
			return err
		}},
		{"Try", func() error {
			fail, err := Try("Try callback", func() error { panic("value of Try") })
			if fail == nil || buf.Len() != 0 {
				t.Errorf("Try: Failure %v, %d octets logged before Report", fail, buf.Len())
			}
			l.Report(fail)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			err := tc.call()
			var ce *CallbackError
			if !errors.As(err, &ce) || ce.Callback != tc.name+" callback" || ce.Value != "value of "+tc.name {
				t.Fatalf("error %#v, want a CallbackError of %q", err, tc.name+" callback")
			}
			if want := tc.name + " callback did not return normally: value of " + tc.name; err.Error() != want {
				t.Errorf("error %q, want %q", err, want)
			}
			out := buf.String()
			for _, want := range []string{`level=ERROR`, `msg="callback did not return normally"`, `callback="` + tc.name + ` callback"`,
				`value="value of ` + tc.name + `"`, `stack="goroutine `, `guard_test.go`} {
				if !strings.Contains(out, want) {
					t.Errorf("entry misses %q:\n%s", want, out)
				}
			}
		})
	}
	// Without a logger the error is returned all the same.
	if err := Run(nil, "f", func() { panic(1) }); err == nil {
		t.Error("Run with a nil logger: no error")
	}
}

func TestLoggerInContext(t *testing.T) {
	l, _ := recorded()
	if FromContext(context.Background()) != nil {
		t.Error("a context without a logger has one")
	}
	if FromContext(NewContext(context.Background(), l)) != l {
		t.Error("the logger of NewContext is not returned")
	}
}

// metricsCalls are the calls of every guarded metrics callback.
var metricsCalls = []struct {
	name string
	call func(dnp3.Metrics, dnp3.RequestMetrics, dnp3.ClientMetrics, dnp3.ServerMetrics)
}{
	{"Metrics.OnConnect", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnConnect(nil)
	}},
	{"Metrics.OnDisconnect", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnDisconnect(nil, nil)
	}},
	{"Metrics.OnFrameSent", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnFrameSent(nil, &link.Frame{}, 10)
	}},
	{"Metrics.OnFrameReceived", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnFrameReceived(nil, &link.Frame{}, 10)
	}},
	{"Metrics.OnFramingError", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnFramingError(nil, nil)
	}},
	{"Metrics.OnFragmentSent", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnFragmentSent(nil, &app.Fragment{}, 4)
	}},
	{"Metrics.OnFragmentReceived", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnFragmentReceived(nil, &app.Fragment{}, 4)
	}},
	{"Metrics.OnDecodeError", func(m dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnDecodeError(nil, nil)
	}},
	{"RequestMetrics.OnRequest", func(_ dnp3.Metrics, m dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnRequest(nil, 10, app.FuncRead)
	}},
	{"RequestMetrics.OnRequestDone", func(_ dnp3.Metrics, m dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnRequestDone(nil, 10, app.FuncRead, time.Second, nil)
	}},
	{"RequestMetrics.OnRetry", func(_ dnp3.Metrics, m dnp3.RequestMetrics, _ dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnRetry(nil, 10, app.FuncRead, 1, nil)
	}},
	{"ClientMetrics.OnTaskDropped", func(_ dnp3.Metrics, _ dnp3.RequestMetrics, m dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnTaskDropped("event-poll")
	}},
	{"ClientMetrics.OnLateResponse", func(_ dnp3.Metrics, _ dnp3.RequestMetrics, m dnp3.ClientMetrics, _ dnp3.ServerMetrics) {
		m.OnLateResponse(nil, app.FuncResponse)
	}},
	{"ServerMetrics.OnHandled", func(_ dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, m dnp3.ServerMetrics) {
		m.OnHandled(nil, app.FuncRead, time.Second)
	}},
	{"ServerMetrics.OnEventsDiscarded", func(_ dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, m dnp3.ServerMetrics) {
		m.OnEventsDiscarded(1, 2)
	}},
	{"ServerMetrics.OnUnsolicited", func(_ dnp3.Metrics, _ dnp3.RequestMetrics, _ dnp3.ClientMetrics, m dnp3.ServerMetrics) {
		m.OnUnsolicited(nil, 3, nil)
	}},
}

// allMetrics implements every metrics interface. With fail set, each
// callback does not return normally; otherwise it records its name.
type allMetrics struct {
	fail  bool
	mu    sync.Mutex
	calls []string
}

func (m *allMetrics) did(name string) {
	if m.fail {
		panic("metrics callback " + name)
	}
	m.mu.Lock()
	m.calls = append(m.calls, name)
	m.mu.Unlock()
}

func (m *allMetrics) OnConnect(net.Addr)                          { m.did("Metrics.OnConnect") }
func (m *allMetrics) OnDisconnect(net.Addr, error)                { m.did("Metrics.OnDisconnect") }
func (m *allMetrics) OnFrameSent(net.Addr, *link.Frame, int)      { m.did("Metrics.OnFrameSent") }
func (m *allMetrics) OnFrameReceived(net.Addr, *link.Frame, int)  { m.did("Metrics.OnFrameReceived") }
func (m *allMetrics) OnFramingError(net.Addr, error)              { m.did("Metrics.OnFramingError") }
func (m *allMetrics) OnFragmentSent(net.Addr, *app.Fragment, int) { m.did("Metrics.OnFragmentSent") }
func (m *allMetrics) OnFragmentReceived(net.Addr, *app.Fragment, int) {
	m.did("Metrics.OnFragmentReceived")
}
func (m *allMetrics) OnDecodeError(net.Addr, error) { m.did("Metrics.OnDecodeError") }
func (m *allMetrics) OnRequest(net.Addr, uint16, app.FunctionCode) {
	m.did("RequestMetrics.OnRequest")
}
func (m *allMetrics) OnRequestDone(net.Addr, uint16, app.FunctionCode, time.Duration, error) {
	m.did("RequestMetrics.OnRequestDone")
}
func (m *allMetrics) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) {
	m.did("RequestMetrics.OnRetry")
}
func (m *allMetrics) OnTaskDropped(string) { m.did("ClientMetrics.OnTaskDropped") }
func (m *allMetrics) OnLateResponse(net.Addr, app.FunctionCode) {
	m.did("ClientMetrics.OnLateResponse")
}
func (m *allMetrics) OnHandled(net.Addr, app.FunctionCode, time.Duration) {
	m.did("ServerMetrics.OnHandled")
}
func (m *allMetrics) OnEventsDiscarded(int, int)         { m.did("ServerMetrics.OnEventsDiscarded") }
func (m *allMetrics) OnUnsolicited(net.Addr, int, error) { m.did("ServerMetrics.OnUnsolicited") }

// TestGuardedMetrics: every callback of the guarded metrics reaches the
// application's; one that does not return normally is logged, naming it,
// and the caller goes on. Nil metrics stay nil.
func TestGuardedMetrics(t *testing.T) {
	if Metrics(nil, nil) != nil || RequestMetrics(nil, nil) != nil || ClientMetrics(nil, nil) != nil || ServerMetrics(nil, nil) != nil {
		t.Fatal("nil metrics are not nil once guarded")
	}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%t", fail), func(t *testing.T) {
			l, buf := recorded()
			m := &allMetrics{fail: fail}
			mm, rm, cm, sm := Metrics(m, l), RequestMetrics(m, l), ClientMetrics(m, l), ServerMetrics(m, l)
			for _, c := range metricsCalls {
				buf.Reset()
				c.call(mm, rm, cm, sm)
				out := buf.String()
				logged := strings.Contains(out, `msg="callback did not return normally"`) &&
					strings.Contains(out, ` callback=`+c.name+` value="metrics callback `+c.name+`"`)
				if logged != fail {
					t.Errorf("%s: logged %t:\n%s", c.name, logged, buf)
				}
			}
			if !fail {
				var want []string
				for _, c := range metricsCalls {
					want = append(want, c.name)
				}
				if strings.Join(m.calls, " ") != strings.Join(want, " ") {
					t.Errorf("calls %v, want %v", m.calls, want)
				}
			}
		})
	}
}

// failingLogger is a FieldLogger and ContextLogger whose methods do not
// return normally, except those named in works. errorf receives the lines
// of Errorf.
type failingLogger struct {
	works  map[string]bool
	errorf []string
}

func (f *failingLogger) do(name string) {
	if !f.works[name] {
		panic("logger method " + name)
	}
}

func (f *failingLogger) Debugf(string, ...any) { f.do("Debugf") }
func (f *failingLogger) Infof(string, ...any)  { f.do("Infof") }
func (f *failingLogger) Warnf(string, ...any)  { f.do("Warnf") }
func (f *failingLogger) Errorf(format string, a ...any) {
	f.do("Errorf")
	f.errorf = append(f.errorf, fmt.Sprintf(format, a...))
}
func (f *failingLogger) With(...any) dnp3.FieldLogger { f.do("With"); return f }
func (f *failingLogger) DebugKV(string, ...any)       { f.do("DebugKV") }
func (f *failingLogger) InfoKV(string, ...any)        { f.do("InfoKV") }
func (f *failingLogger) WarnKV(string, ...any)        { f.do("WarnKV") }
func (f *failingLogger) ErrorKV(string, ...any)       { f.do("ErrorKV") }
func (f *failingLogger) DebugContext(context.Context, string, ...any) {
	f.do("DebugContext")
}
func (f *failingLogger) InfoContext(context.Context, string, ...any) { f.do("InfoContext") }
func (f *failingLogger) WarnContext(context.Context, string, ...any) { f.do("WarnContext") }
func (f *failingLogger) ErrorContext(context.Context, string, ...any) {
	f.do("ErrorContext")
}
func (f *failingLogger) DebugEnabled() bool { f.do("DebugEnabled"); return true }

// TestLoggerThatDoesNotReturnNormally: a call of the application's logger
// that does not return normally loses its entry, and the failure is
// written through Errorf as a formatted line, with the stack; the caller
// goes on. A With that does not return normally leaves the formatted path,
// a DebugEnabled that does not says false, and when Errorf does not
// return normally either, nothing escapes.
func TestLoggerThatDoesNotReturnNormally(t *testing.T) {
	f := &failingLogger{works: map[string]bool{"Errorf": true}}
	l := New(f, "test")
	if l.fields != nil {
		t.Error("a With that does not return normally kept the structured path")
	}
	if l.DebugEnabled() {
		t.Error("a DebugEnabled that does not return normally reads as true")
	}
	ctx := context.Background()
	for _, write := range []func(){
		func() { l.Debug("d") },
		func() { l.Info("i") },
		func() { l.Warn("w") },
		func() { l.DebugContext(ctx, "dc") },
		func() { l.WarnContext(ctx, "wc") },
	} {
		f.errorf = nil
		write()
		if len(f.errorf) != 1 || !strings.Contains(f.errorf[0], "dnp3 test: callback did not return normally callback=Logger value=logger method ") ||
			!strings.Contains(f.errorf[0], "stack=goroutine ") {
			t.Errorf("failure written as %q", f.errorf)
		}
	}
	// With on a structured logger whose With fails later.
	f.works["With"] = true
	l = New(f, "test")
	f.works["With"] = false
	if w := l.With("k", "v"); w.fields != nil {
		t.Error("With: a With that does not return normally kept the structured path")
	}
	// Errorf fails too: nothing reaches the caller.
	f.works["Errorf"] = false
	l.Error("e")
	l.Info("i")
}
