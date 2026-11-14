// SPDX-License-Identifier: MIT

package client

import (
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

// benchMeasurements is the result of the benchmark, kept so that the work
// is not optimised away.
var benchMeasurements []Measurement

// BenchmarkMeasurements turns a decoded response fragment of packed binary
// inputs, analog inputs and analog events into measurements, as the
// client does for every fragment it hands to the Handler.
func BenchmarkMeasurements(b *testing.B) {
	bits := make([]app.Value, 4000)
	for i := range bits {
		bits[i] = app.Binary{Value: i%2 == 0}
	}
	analogs := make([]app.Value, 200)
	for i := range analogs {
		analogs[i] = app.Analog{Value: float64(i), Flags: app.FlagOnline}
	}
	events := make([]app.Object, 50)
	for i := range events {
		events[i] = app.Object{Index: uint32(i), Value: app.Analog{Value: 1, Flags: app.FlagOnline, Time: 1_700_000_000_000}}
	}
	enc, err := (&app.Fragment{Control: app.SingleControl(0), Function: app.FuncResponse, Headers: []app.Header{
		app.Ranged(app.G1V1, 0, bits...), app.Ranged(app.G30V5, 0, analogs...), app.Indexed(app.G32V7, events...),
	}}).Encode()
	if err != nil {
		b.Fatal(err)
	}
	f, err := app.Decode(enc)
	if err != nil {
		b.Fatal(err)
	}
	if n := len(Measurements(f)); n != len(bits)+len(analogs)+len(events) {
		b.Fatalf("%d measurements", n)
	}
	b.SetBytes(int64(len(enc)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchMeasurements = Measurements(f)
	}
}
