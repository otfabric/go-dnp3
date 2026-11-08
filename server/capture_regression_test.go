// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

// Regression tests for defects found by replaying recorded traffic
// (testdata/captures/README.md).

// TestReadAttributeVariationZero: a READ of g0v0 names no object (device
// attributes are variations 1..255) and is answered with IIN2.1 alone,
// with or without device attributes. Before, an outstation without
// attribute sets answered IIN2.2 (PARAMETER_ERROR). Recorded:
// conformance-runner_opendnp3-3_8-6-3-2.pcap frame 4, where the DNP3 IED
// certification procedure 8.6.3.2 verifies IIN(ObjectUnknown).
func TestReadAttributeVariationZero(t *testing.T) {
	for name, opts := range map[string][]Option{
		"no attributes":   nil,
		"with attributes": {WithAttributes(map[uint8]app.Attribute{app.AttrManufacturerName: app.StringAttribute("x")})},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMaster(t, opts...)
			m.send(req(1, app.FuncRead, app.AllObjects(app.GV(0, 0))))
			r := m.recvFunc(app.FuncResponse)
			if got := r.IIN & (app.IINObjectUnknown | app.IINParameterError | app.IINNoFuncCodeSupport); got != app.IINObjectUnknown || len(r.Headers) != 0 {
				t.Fatalf("READ g0v0: IIN %s, %d headers; want OBJECT_UNKNOWN alone", r.IIN, len(r.Headers))
			}
		})
	}
}
