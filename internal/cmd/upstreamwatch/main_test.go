// SPDX-License-Identifier: MIT

package main

import (
	"reflect"
	"testing"
)

func TestParseStepfunc(t *testing.T) {
	src := `
object Group1Var0 extends AnyVariation(Group1, 0)
object Group1Var2 extends FixedSize(Group1, 2, "with flags")(flags)
object Group9Var9 extends FixedSize(Group9, 9, "nested")(
  time48,
  FixedSizeField("a", UInt32Field),
  FixedSizeField("b", EnumFieldType(Some.Enum)),
  commandStatus
)
object Group9Var8 extends FreeFormat(Group9, 8, "free")
object Group9Var7 extends FixedSize(Group9, 7, "unknown")(mystery)
`
	defs, skipped := parseStepfunc(src)
	want := map[key]int{{1, 2}: 1, {9, 9}: 12}
	if !reflect.DeepEqual(defs, want) || skipped != 2 {
		t.Fatalf("got %v, %d skipped; want %v, 2 skipped", defs, skipped, want)
	}
}

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
