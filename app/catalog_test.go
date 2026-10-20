// SPDX-License-Identifier: MIT

package app

import (
	"encoding/json"
	"os"
	"testing"
)

// TestCatalog checks the codec against the catalog it is generated from:
// every object of app/catalog.json is known with its name, event kind and
// size, and the table holds nothing else. The size is the octets the
// standard gives one object; the codec computes it from the family.
func TestCatalog(t *testing.T) {
	b, err := os.ReadFile("catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Objects []struct {
			Group     uint8  `json:"group"`
			Variation uint8  `json:"variation"`
			Name      string `json:"name"`
			Event     bool   `json:"event"`
			Size      *int   `json:"size"`
		} `json:"objects"`
		OpenGroups []struct {
			Group uint8 `json:"group"`
		} `json:"openGroups"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	for _, o := range c.Objects {
		gv := GV(o.Group, o.Variation)
		if !gv.Known() || gv.Name() != o.Name || gv.IsEvent() != o.Event {
			t.Errorf("%s: known %v, name %q, event %v; catalog %q, event %v", gv, gv.Known(), gv.Name(), gv.IsEvent(), o.Name, o.Event)
		}
		n, fixed := gv.Size()
		switch {
		case o.Size == nil && fixed:
			t.Errorf("%s: the codec says %d octets, the catalog not fixed", gv, n)
		case o.Size != nil && (!fixed || n != *o.Size):
			t.Errorf("%s: the codec says %d octets (fixed %v), the catalog %d", gv, n, fixed, *o.Size)
		}
	}
	if len(table) != len(c.Objects) {
		t.Errorf("the table has %d objects, the catalog %d", len(table), len(c.Objects))
	}
	for _, og := range c.OpenGroups {
		if !GV(og.Group, 1).Known() {
			t.Errorf("open group %d unknown", og.Group)
		}
	}
}
