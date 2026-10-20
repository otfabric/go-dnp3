// SPDX-License-Identifier: MIT

package secauth

import (
	"slices"
	"testing"

	"github.com/otfabric/go-dnp3/app"
)

func TestStatistics(t *testing.T) {
	if NumStatistics != 18 {
		t.Fatalf("%d statistics, IEEE 1815-2012 has 18", NumStatistics)
	}
	names := map[string]bool{}
	for s := range NumStatistics {
		n := s.String()
		if n == "" || names[n] {
			t.Fatalf("statistic %d: name %q", s, n)
		}
		names[n] = true
	}
	if StatSessionKeyChanges.String() != "session key changes" || Statistic(18).String() != "statistic 18" {
		t.Fatal("statistic names")
	}
	if !slices.Contains(DefaultCritical, app.FuncDirectOperate) || slices.Contains(DefaultCritical, app.FuncRead) {
		t.Fatal("default critical function codes")
	}
}
