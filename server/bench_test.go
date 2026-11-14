// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

// benchResponse is the result of the benchmark, kept so that the work is
// not optimised away.
var benchResponse *response

// BenchmarkReadWholeDatabase plans and packs the response to a class 0
// READ of a database of 1000 binary inputs, 1000 analog inputs, 500
// counters and 100 octet strings, on the association's goroutine as a
// request is handled.
func BenchmarkReadWholeDatabase(b *testing.B) {
	srv, err := New(WithMasters(1))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = srv.Close() })
	db := srv.Database()
	for i := range uint32(1000) {
		_ = db.AddBinaryInput(i, PointConfig{Class: 1}, app.Binary{Value: i%2 == 0, Flags: app.FlagOnline})
		_ = db.AddAnalogInput(i, PointConfig{Class: 2}, app.Analog{Value: float64(i), Flags: app.FlagOnline})
	}
	for i := range uint32(500) {
		_ = db.AddCounter(i, PointConfig{Class: 3}, app.Counter{Value: i, Flags: app.FlagOnline})
	}
	for i := range uint32(100) {
		_ = db.Add(OctetString, i, PointConfig{}, app.OctetString{Data: []byte("value")})
	}
	a := srv.association(1)
	req := &app.Fragment{Control: app.SingleControl(0), Function: app.FuncRead, Headers: app.ClassHeaders(0)}
	run := func(n int) *response {
		var r *response
		done := make(chan struct{})
		a.post(func() {
			defer close(done)
			for range n {
				r = a.read(req)
			}
		})
		<-done
		return r
	}
	r := run(1)
	if r.iin&(app.IINObjectUnknown|app.IINParameterError) != 0 || len(r.plans) == 0 {
		b.Fatalf("READ answered with IIN %s and %d fragments", r.iin, len(r.plans))
	}
	size := 0
	for _, p := range r.plans {
		f := &app.Fragment{Control: app.SingleControl(0), Function: app.FuncResponse, Headers: p.headers}
		enc, err := f.Encode()
		if err != nil {
			b.Fatal(err)
		}
		size += len(enc)
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	benchResponse = run(b.N)
}
