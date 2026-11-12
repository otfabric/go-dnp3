// SPDX-License-Identifier: MIT

package capture

import (
	"bufio"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// tsharkFrame is one line of testdata/captures/tshark/: what Wireshark's
// DNP3 dissector decoded in one capture frame. Each field holds one value
// per occurrence, in the order of the frame.
type tsharkFrame struct {
	frame                                  int
	ctl, src, dst, length, trCtl           []string
	alCtl, alFunc, alIIN, obj, prefix, rng []string
}

func readTshark(t *testing.T, local string) map[int]tsharkFrame {
	t.Helper()
	p := filepath.Join("tshark", strings.TrimSuffix(local, ".pcap")+".tsv")
	f, err := openRoot(t, capturesDir).Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[int]tsharkFrame{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != 12 {
			t.Fatalf("%s: %d columns: %q", p, len(c), line)
		}
		n, err := strconv.Atoi(c[0])
		if err != nil {
			t.Fatal(err)
		}
		split := func(s string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, "|")
		}
		out[n] = tsharkFrame{frame: n, ctl: split(c[1]), src: split(c[2]), dst: split(c[3]), length: split(c[4]),
			trCtl: split(c[5]), alCtl: split(c[6]), alFunc: split(c[7]), alIIN: split(c[8]), obj: split(c[9]),
			prefix: split(c[10]), rng: split(c[11])}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func hex8(v uint8) string   { return fmt.Sprintf("0x%02x", v) }
func hex16(v uint16) string { return fmt.Sprintf("0x%04x", v) }

// ourFrame is go-dnp3's decoding of one capture frame in the same form.
func ourFrames(r Recording) map[int]tsharkFrame {
	out := map[int]tsharkFrame{}
	for _, s := range r.Conversations {
		for _, lf := range s.Links {
			if lf.Err != nil {
				continue
			}
			t := out[lf.Frame]
			t.ctl = append(t.ctl, hex8(lf.Link.Control()))
			t.src = append(t.src, strconv.Itoa(int(lf.Link.Src)))
			t.dst = append(t.dst, strconv.Itoa(int(lf.Link.Dest)))
			t.length = append(t.length, strconv.Itoa(5+len(lf.Link.Data)))
			if len(lf.Link.Data) > 0 {
				t.trCtl = append(t.trCtl, hex8(lf.Link.Data[0]))
			}
			out[lf.Frame] = t
		}
		for _, f := range s.Fragments {
			if f.Frag == nil {
				continue
			}
			t := out[f.Frame]
			t.alCtl = append(t.alCtl, hex8(f.Frag.Control.Byte()))
			t.alFunc = append(t.alFunc, strconv.Itoa(int(f.Frag.Function)))
			if f.Frag.Function.IsResponse() {
				t.alIIN = append(t.alIIN, hex16(uint16(f.Frag.IIN.IIN1())<<8|uint16(f.Frag.IIN.IIN2())))
			}
			for _, h := range f.Frag.Headers {
				t.obj = append(t.obj, hex16(uint16(h.GV)))
				t.prefix = append(t.prefix, strconv.Itoa(int(h.Qualifier>>4&7)))
				t.rng = append(t.rng, strconv.Itoa(int(h.Qualifier&0x0F)))
			}
			out[f.Frame] = t
		}
	}
	return out
}

// tsharkExpected are the frames where go-dnp3's decoding differs from
// Wireshark's, by file, with the classification.
var tsharkExpected = map[string]struct {
	frames []int
	why    string
}{
	"assign-class": {[]int{1}, "oracle limitation: Wireshark lists no object headers of ASSIGN_CLASS; go-dnp3 decodes g60v3 and g1v0 (qualifier 0x06), as the request carries"},
	"direct-operate-crob-malform-but-good-crc": {[]int{1}, "legitimate refusal: the g12v1 header announces 2 objects in 13 octets; Wireshark shows the header, app.Decode refuses the fragment"},
	"test-data-part1":                          {[]int{154, 156, 163, 166, 174, 176}, "legitimate refusal: g60v4 with qualifier 0xED, which IEEE 1815-2012 does not define; Wireshark shows it with an unknown range type, app.Decode refuses the fragment"},
	"zeek-test-data-merged":                    {[]int{154, 156, 163, 166, 174, 176}, "the fragments of test-data-part1"},
	"write-vto-empty-string":                   {[]int{2}, "legitimate protocol variation: 285 headers g112v0 with qualifier 0x01 and no objects; Wireshark stops after the first, app.Decode reads all (each names objects of size 0, so none follow); the outstation answers IIN2.1"},
	"conformance-6-6-2-2":                      {[]int{14, 16}, "legitimate refusal: undefined primary function codes 5 and 10 (IEEE 1815-2012 clause 9.2.4.1.3); Wireshark decodes the frames"},
	"conformance-6-6-2-3":                      {[]int{4, 6}, "legitimate refusal: UNCONFIRMED_USER_DATA with length octet 5 and a data block after it; Wireshark decodes the header"},
	"conformance-6-6-2-4":                      {[]int{6, 10}, "legitimate refusal: as 6.6.2.3, length octet 5 with a data block after it"},
	"conformance-6-6-2-5":                      {[]int{8, 10, 12}, "legitimate refusal: link functions without user data sent with 15 octets of it; Wireshark decodes them"},
}

// TestTshark: go-dnp3 decodes every capture frame as Wireshark's DNP3
// dissector does (testdata/captures/tshark, scripts/captures-oracle.sh):
// the link header of every frame (control, addresses, length), the
// transport header, and the application header (control, function, IIN)
// and object headers (group, variation, qualifier) of every fragment, in
// the frame that completed it. The differences are classified in
// tsharkExpected.
func TestTshark(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	var frames, links, frags int
	for _, r := range recs {
		ts := readTshark(t, r.File.Local)
		ours := ourFrames(r)
		keys := map[int]bool{}
		for n := range ts {
			keys[n] = true
		}
		for n := range ours {
			keys[n] = true
		}
		var differ []int
		for n := range keys {
			a, b := ts[n], ours[n]
			frames++
			links += len(b.ctl)
			frags += len(b.alFunc)
			for _, c := range [][2][]string{{a.ctl, b.ctl}, {a.src, b.src}, {a.dst, b.dst}, {a.length, b.length}, {a.trCtl, b.trCtl},
				{a.alCtl, b.alCtl}, {a.alFunc, b.alFunc}, {a.alIIN, b.alIIN}, {a.obj, b.obj}, {a.prefix, b.prefix}, {a.rng, b.rng}} {
				if !slices.Equal(c[0], c[1]) {
					differ = append(differ, n)
					break
				}
			}
		}
		slices.Sort(differ)
		if want := tsharkExpected[r.File.ID].frames; !slices.Equal(differ, want) {
			for _, n := range differ {
				if !slices.Contains(want, n) {
					a, b := ts[n], ours[n]
					t.Errorf("%s frame %d: Wireshark %+v, go-dnp3 %+v", r.File.ID, n, a, b)
				}
			}
			t.Errorf("%s: frames %v differ from Wireshark, classified %v", r.File.ID, differ, want)
		}
	}
	t.Logf("%d capture frames with DNP3: %d link frames and %d fragments compared with Wireshark", frames, links, frags)
}
