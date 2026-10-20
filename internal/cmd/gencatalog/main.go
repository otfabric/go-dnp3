// SPDX-License-Identifier: MIT

// Command gencatalog generates the code and documentation that follow
// from the DNP3 object catalog, app/catalog.json:
//
//   - app/registry_table.go: the group and variation constants and the
//     table of the app package's codec for each;
//   - client/points_table.go: which objects client.Measurements reports;
//   - OBJECTS.md: the catalog as a document.
//
// Run it from the module root with go generate ./... (doc.go carries the
// directive). CI fails when the generated files differ from what the
// catalog says.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strings"
)

// Object is one group and variation of the catalog.
type Object struct {
	Group     uint8  `json:"group"`
	Variation uint8  `json:"variation"`
	Name      string `json:"name"`
	Family    string `json:"family"`
	Number    string `json:"number"`
	Flags     bool   `json:"flags"`
	Time      string `json:"time"`
	Event     bool   `json:"event"`
	Size      *int   `json:"size"`
	Point     bool   `json:"point"`
}

// OpenGroup is a group whose variation is not a fixed set.
type OpenGroup struct {
	Group      uint8  `json:"group"`
	Name       string `json:"name"`
	Variations string `json:"variations"`
	Event      bool   `json:"event"`
	Point      bool   `json:"point"`
}

// Catalog is app/catalog.json.
type Catalog struct {
	Standard   string      `json:"standard"`
	Objects    []Object    `json:"objects"`
	OpenGroups []OpenGroup `json:"openGroups"`
}

var families = map[string]string{
	"none": "fNone", "any": "fAny", "binaryPacked": "fBinaryPacked", "binary": "fBinary",
	"doubleBitPacked": "fDoubleBitPacked", "doubleBit": "fDoubleBit", "binaryCommandEvent": "fBinaryCommandEvent",
	"crob": "fCROB", "counter": "fCounter", "analog": "fAnalog", "deadband": "fDeadband",
	"analogOutput": "fAnalogOutput", "analogCommandEvent": "fAnalogCommandEvent", "time": "fTime",
	"timeInterval": "fTimeInterval", "timeIntervalUnits": "fTimeIntervalUnits", "cto": "fCTO",
	"delayCoarse": "fDelayCoarse", "delayFine": "fDelayFine", "octets": "fOctets", "bcd": "fBCD",
	"uint8": "fUint8", "dataSetChars": "fDataSetChars", "secStat": "fSecStat", "attribute": "fAttribute", "raw": "fRaw",
	"fileAuth": "fFileAuth", "fileCommand": "fFileCommand", "fileCommandStatus": "fFileCommandStatus",
	"fileTransport": "fFileTransport", "fileTransportStatus": "fFileTransportStatus",
	"fileDescriptor": "fFileDescriptor", "fileSpec": "fFileSpec", "auth": "fAuth",
}

var numbers = map[string]string{"": "", "int16": "nI16", "int32": "nI32", "uint16": "nU16", "uint32": "nU32", "float32": "nF32", "float64": "nF64"}

var times = map[string]string{"": "", "absolute": "tAbs", "relative": "tRel"}

func main() {
	check := flag.Bool("check", false, "compare the generated files with what the catalog generates, and fail when they differ, instead of writing them")
	flag.Parse()
	if err := run("app/catalog.json", *check); err != nil {
		fmt.Fprintln(os.Stderr, "gencatalog:", err)
		os.Exit(1)
	}
}

func run(path string, check bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c Catalog
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var stale []string
	for _, out := range []struct {
		path string
		gen  func(*Catalog) ([]byte, error)
	}{
		{"app/registry_table.go", registryTable},
		{"client/points_table.go", pointsTable},
		{"OBJECTS.md", objectsDoc},
	} {
		b, err := out.gen(&c)
		if err != nil {
			return fmt.Errorf("%s: %w", out.path, err)
		}
		if check {
			have, err := os.ReadFile(out.path)
			if err != nil || !bytes.Equal(have, b) {
				stale = append(stale, out.path)
			}
			continue
		}
		if err := os.WriteFile(out.path, b, 0o644); err != nil {
			return err
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("out of date with app/catalog.json: %s; run make generate", strings.Join(stale, ", "))
	}
	return nil
}

func (c *Catalog) validate() error {
	seen := map[[2]uint8]bool{}
	for i, o := range c.Objects {
		k := [2]uint8{o.Group, o.Variation}
		switch {
		case seen[k]:
			return fmt.Errorf("g%dv%d twice", o.Group, o.Variation)
		case o.Name == "":
			return fmt.Errorf("g%dv%d without a name", o.Group, o.Variation)
		case families[o.Family] == "":
			return fmt.Errorf("g%dv%d: unknown family %q", o.Group, o.Variation, o.Family)
		case o.Number != "" && numbers[o.Number] == "":
			return fmt.Errorf("g%dv%d: unknown number %q", o.Group, o.Variation, o.Number)
		case o.Time != "" && times[o.Time] == "":
			return fmt.Errorf("g%dv%d: unknown time %q", o.Group, o.Variation, o.Time)
		case o.Size != nil && *o.Size <= 0:
			return fmt.Errorf("g%dv%d: size %d", o.Group, o.Variation, *o.Size)
		case o.Variation == 0 && o.Point:
			return fmt.Errorf("g%dv0 (any variation) marked as a point", o.Group)
		}
		if i > 0 {
			p := c.Objects[i-1]
			if p.Group > o.Group || p.Group == o.Group && p.Variation > o.Variation {
				return fmt.Errorf("g%dv%d is out of order", o.Group, o.Variation)
			}
		}
		seen[k] = true
	}
	return nil
}

func ident(o Object) string { return fmt.Sprintf("G%dV%d", o.Group, o.Variation) }

const generated = "// Code generated by internal/cmd/gencatalog from app/catalog.json. DO NOT EDIT.\n\n"

func registryTable(c *Catalog) ([]byte, error) {
	var w bytes.Buffer
	w.WriteString("// SPDX-License-Identifier: MIT\n\n" + generated)
	w.WriteString("package app\n\n")
	fmt.Fprintf(&w, "// Group and variation constants for every object this package encodes and\n// decodes, from %s. Variation 0 of a group is \"any variation\"\n// in a request.\n//\n", c.Standard)
	w.WriteString("// Group 0 (device attributes) and groups 110..113 (octet strings, whose\n// variation is the length) are open-ended: build those with [GV].\nconst (\n")
	for _, o := range c.Objects {
		if o.Variation == 0 {
			fmt.Fprintf(&w, "\t%s GroupVariation = %d << 8 // %s\n", ident(o), o.Group, o.Name)
		} else {
			fmt.Fprintf(&w, "\t%s GroupVariation = %d<<8 | %d // %s\n", ident(o), o.Group, o.Variation, o.Name)
		}
	}
	w.WriteString(")\n\nvar table = map[GroupVariation]*desc{\n")
	for _, o := range c.Objects {
		fields := []string{fmt.Sprintf("name: %q", o.Name), "fam: " + families[o.Family]}
		if o.Number != "" {
			fields = append(fields, "num: "+numbers[o.Number])
		}
		if o.Flags {
			fields = append(fields, "flags: true")
		}
		if o.Time != "" {
			fields = append(fields, "time: "+times[o.Time])
		}
		if o.Event {
			fields = append(fields, "event: true")
		}
		fmt.Fprintf(&w, "\t%s: {%s},\n", ident(o), strings.Join(fields, ", "))
	}
	w.WriteString("}\n")
	return format.Source(w.Bytes())
}

func pointsTable(c *Catalog) ([]byte, error) {
	// A group is a point group when every variation of it the catalog has
	// (variation 0 aside) is a point; the other points are named one by one.
	byGroup := map[uint8][]Object{}
	for _, o := range c.Objects {
		if o.Variation != 0 {
			byGroup[o.Group] = append(byGroup[o.Group], o)
		}
	}
	var groups []int
	var single []string
	for g, os := range byGroup {
		all := true
		for _, o := range os {
			all = all && o.Point
		}
		if all {
			groups = append(groups, int(g))
			continue
		}
		for _, o := range os {
			if o.Point {
				single = append(single, "app."+ident(o))
			}
		}
	}
	for _, og := range c.OpenGroups {
		if og.Point {
			groups = append(groups, int(og.Group))
		}
	}
	sort.Ints(groups)
	sort.Strings(single)
	var w bytes.Buffer
	w.WriteString("// SPDX-License-Identifier: MIT\n\n" + generated)
	w.WriteString("package client\n\nimport \"github.com/otfabric/go-dnp3/app\"\n\n")
	w.WriteString("// isMeasurement reports whether objects of gv are point data, which\n// Measurements reports: the objects the catalog marks as points.\n")
	w.WriteString("func isMeasurement(gv app.GroupVariation) bool {\n\tswitch gv.Group() {\n\tcase ")
	gs := make([]string, len(groups))
	for i, g := range groups {
		gs[i] = fmt.Sprint(g)
	}
	w.WriteString(strings.Join(gs, ", ") + ":\n\t\treturn gv.Variation() != 0\n\t}\n")
	if len(single) > 0 {
		w.WriteString("\tswitch gv {\n\tcase " + strings.Join(single, ", ") + ":\n\t\treturn true\n\t}\n")
	}
	w.WriteString("\treturn false\n}\n")
	return format.Source(w.Bytes())
}

func objectsDoc(c *Catalog) ([]byte, error) {
	var w bytes.Buffer
	w.WriteString("<!-- Code generated by internal/cmd/gencatalog from app/catalog.json. DO NOT EDIT. -->\n\n")
	w.WriteString("# DNP3 objects\n\n")
	fmt.Fprintf(&w, "Every group and variation the `app` package encodes and decodes, from %s.\n", c.Standard)
	w.WriteString("The catalog [`app/catalog.json`](app/catalog.json) is the source: this page, the\nconstants and table of the `app` package and the objects `client.Measurements`\nreports are generated from it.\n\n")
	w.WriteString("**Size** is the octets of one object; \"—\" when it is not fixed (packed bits,\nfree-format and variable-length objects). **Point** marks the indexed data\n`client.Measurements` reports: the values and events of the point types,\ntheir deadbands (g34), BCD and unsigned integers (g101, g102) and the\nsecurity statistics (g121, g122), each sent with the index of its point.\nObjects about the device or a procedure are not points, even in a group\nthat has one: the time and date of time synchronization (g50v1, g50v3)\nand the freeze time (g50v2) have no index, while g50v4, the time and\ninterval point type, does. **Kind** is \"static\" for the current value of\na point, \"event\" for an event, \"any variation\" for variation 0 in a\nrequest, and \"other\" for commands, procedure objects and the rest.\n\n")
	w.WriteString("| Object | Name | Kind | Size | Point |\n|---|---|---|---:|:---:|\n")
	for _, o := range c.Objects {
		kind := "other"
		switch {
		case o.Event:
			kind = "event"
		case o.Point:
			kind = "static"
		}
		if o.Variation == 0 {
			kind = "any variation"
		}
		size := "—"
		if o.Size != nil {
			size = fmt.Sprint(*o.Size)
		}
		point := ""
		if o.Point {
			point = "✓"
		}
		fmt.Fprintf(&w, "| g%dv%d | %s | %s | %s | %s |\n", o.Group, o.Variation, o.Name, kind, size, point)
	}
	w.WriteString("\n## Open-ended groups\n\nTheir variation is not a fixed set; the `app` package handles them in code.\n\n")
	w.WriteString("| Group | Name | Variation | Point |\n|---|---|---|:---:|\n")
	for _, og := range c.OpenGroups {
		point := ""
		if og.Point {
			point = "✓"
		}
		fmt.Fprintf(&w, "| g%d | %s | %s | %s |\n", og.Group, og.Name, og.Variations, point)
	}
	return w.Bytes(), nil
}
