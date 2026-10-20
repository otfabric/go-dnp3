// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"sync"
	"testing"

	dnp3 "github.com/otfabric/go-dnp3"
	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/server"
)

// setWriter records the writes of attribute sets and refuses one value.
type setWriter struct {
	relay
	mu     sync.Mutex
	writes []string
}

func (w *setWriter) WriteAttributeSet(_ context.Context, set uint16, v uint8, a app.Attribute) error {
	if string(a.Data) == "refused" {
		return errors.New("refused")
	}
	w.mu.Lock()
	w.writes = append(w.writes, string(a.Data))
	w.mu.Unlock()
	return nil
}

func TestAttributeSets(t *testing.T) {
	w := &setWriter{relay: relay{status: app.StatusSuccess}}
	p := newPair(t, nil, []server.Option{
		server.WithHandler(w),
		server.WithAttributes(map[uint8]app.Attribute{app.AttrManufacturerName: app.StringAttribute("set zero")}),
		server.WithAttributeSet(1, map[uint8]app.Attribute{
			1:  app.StringAttribute("read only"),
			10: app.StringAttribute("writable text"),
			11: app.UintAttribute(7),
		}, 10, 11),
	})
	c := ctx(t)
	got, err := p.c.ReadAttributeSet(c, 1, app.AttrAllAttributes)
	if err != nil || len(got) != 3 || string(got[1].Data) != "read only" {
		t.Fatalf("set 1: %v %v", got, err)
	}
	list, err := p.c.ReadAttributeSet(c, 1, app.AttrListOfVariations)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := list[app.AttrListOfVariations].List()
	writable := map[uint8]bool{}
	for _, e := range entries {
		writable[e.Variation] = e.Writable
	}
	if writable[1] || !writable[10] || !writable[11] {
		t.Fatalf("writable variations %v", writable)
	}
	if zero, err := p.c.ReadAttributes(c, app.AttrManufacturerName); err != nil || string(zero[app.AttrManufacturerName].Data) != "set zero" {
		t.Fatalf("set 0: %v %v", zero, err)
	}
	// A writable attribute is stored; read only, another type, a refusal
	// by the handler and an unknown set are refused.
	if err := p.c.WriteAttributeSet(c, 1, 10, app.StringAttribute("changed")); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.c.ReadAttributeSet(c, 1, 10); string(got[10].Data) != "changed" {
		t.Fatalf("after the write: %v", got)
	}
	var ie *dnp3.IINError
	for name, write := range map[string]func() error{
		"read only":    func() error { return p.c.WriteAttributeSet(c, 1, 1, app.StringAttribute("x")) },
		"another type": func() error { return p.c.WriteAttributeSet(c, 1, 11, app.StringAttribute("x")) },
		"refused":      func() error { return p.c.WriteAttributeSet(c, 1, 10, app.StringAttribute("refused")) },
		"unknown set":  func() error { return p.c.WriteAttributeSet(c, 9, 10, app.StringAttribute("x")) },
		"set 0 without a WriteHandler": func() error {
			return p.c.WriteAttribute(c, app.AttrManufacturerName, app.StringAttribute("x"))
		},
	} {
		if err := write(); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := p.c.ReadAttributeSet(c, 9, app.AttrAllAttributes); !errors.As(err, &ie) {
		t.Errorf("read of an unknown set: %v", err)
	}
	if len(w.writes) != 1 || w.writes[0] != "changed" {
		t.Errorf("handler saw %v", w.writes)
	}
	if _, err := server.New(server.WithAttributeSet(2, map[uint8]app.Attribute{1: app.UintAttribute(1)}, 5)); err == nil {
		t.Error("a writable variation that does not exist was accepted")
	}
}
