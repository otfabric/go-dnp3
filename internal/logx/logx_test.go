// SPDX-License-Identifier: MIT

package logx

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
)

func TestNilLoggerDiscards(t *testing.T) {
	var l *Logger
	if New(nil, "client") != nil || l.With("a", 1) != nil || l.DebugEnabled() {
		t.Fatal("a nil base must give a nil, disabled logger")
	}
	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x")
	l.DebugContext(context.Background(), "x")
	l.WarnContext(context.Background(), "x")
}

func TestFormattedPath(t *testing.T) {
	var buf bytes.Buffer
	l := New(dnp3.NewStdLogger(log.New(&buf, "", 0)), "server").With("session", 3)
	if !l.DebugEnabled() {
		t.Error("a logger that cannot tell is assumed to take debug entries")
	}
	l.Debug("frame sent", "format", "S", "nr", 7)
	l.Info("listening", "address", ":2404")
	l.Warn("rejected")
	l.Error("handler panic", "panic", "boom")
	l.DebugContext(context.Background(), "request", "type", "C_IC_NA_1")
	l.WarnContext(context.Background(), "retrying", "attempt", 1)
	want := "DEBUG dnp3 server session=3: frame sent format=S nr=7\n" +
		"INFO  dnp3 server session=3: listening address=:2404\n" +
		"WARN  dnp3 server session=3: rejected\n" +
		"ERROR dnp3 server session=3: handler panic panic=boom\n" +
		"DEBUG dnp3 server session=3: request type=C_IC_NA_1\n" +
		"WARN  dnp3 server session=3: retrying attempt=1\n"
	if buf.String() != want {
		t.Errorf("got:\n%swant:\n%s", buf.String(), want)
	}
}

func TestStructuredPath(t *testing.T) {
	var buf bytes.Buffer
	base := dnp3.NewSlogLogger(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	l := New(base, "client", "remote", "10.0.0.5:2404").With("path", "a")
	if l.DebugEnabled() {
		t.Error("DebugEnabled at info level")
	}
	l.Debug("dropped")
	l.Info("connection state", "state", "started")
	l.Warn("w")
	l.Error("e")
	l.WarnContext(context.Background(), "retrying", "attempt", 2)
	l.DebugContext(context.Background(), "dropped too")
	out := buf.String()
	for _, want := range []string{
		`level=INFO msg="connection state" component=dnp3.client remote=10.0.0.5:2404 path=a state=started`,
		`level=WARN msg=w component=dnp3.client`, `level=ERROR msg=e component=dnp3.client`,
		`level=WARN msg=retrying component=dnp3.client remote=10.0.0.5:2404 path=a attempt=2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("misses %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dropped") {
		t.Errorf("debug entries written at info level:\n%s", out)
	}
}
