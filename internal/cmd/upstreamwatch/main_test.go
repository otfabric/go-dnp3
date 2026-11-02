// SPDX-License-Identifier: MIT

package main

import (
	"reflect"
	"testing"
)

func TestParseDSC(t *testing.T) {
	src := `objects:
  - {group: 1, variation: 2, name: "a", fields: [{name: flags, type: flags}]}
  - {group: 9, variation: 9, name: "b",
     fields: [{name: t, type: time48}, {name: v, type: f64}]}
  - {group: 1, variation: 1, packed: true, fields: [{name: v, type: u8}]}
  - {group: 9, variation: 8, variable: true}
  - {group: 9, variation: 7, fields: [{name: x, type: mystery}]}
`
	defs, skipped := parseDSC(src)
	want := map[key]int{{1, 2}: 1, {9, 9}: 14}
	if !reflect.DeepEqual(defs, want) || skipped != 3 {
		t.Fatalf("got %v, %d skipped; want %v, 3 skipped", defs, skipped, want)
	}
}
