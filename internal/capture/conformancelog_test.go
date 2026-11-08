// SPDX-License-Identifier: MIT

package capture

import (
	"encoding/hex"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
	"github.com/otfabric/go-dnp3/transport"
)

// The conformance runner's log.html records, for every frame it sent
// (--P->) or received (<-P--), the physical octets and its own decoding of
// the link (L), transport (T) and application (A) layers. It is an
// independent decoder of the same bytes: these tests hold go-dnp3's
// reassembly and decoding of the capture against it.

// logEntry is one marked row of a log with its continuation rows.
type logEntry struct {
	send  bool   // transmitted by the runner (the master)
	layer byte   // 'P', 'L', 'T' or 'A'
	text  string // first row
	more  []string
}

var (
	logRow    = regexp.MustCompile(`(?s)<tr class="([^"]*)">\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*</tr>`)
	logSpaces = regexp.MustCompile(`\s+`)
)

func readLog(t *testing.T, local string) []logEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(capturesDir, filepath.FromSlash(local)))
	if err != nil {
		t.Fatal(err)
	}
	var out []logEntry
	for _, m := range logRow.FindAllStringSubmatch(string(b), -1) {
		cls := m[1]
		marker := strings.TrimSpace(m[3])
		text := strings.TrimSpace(logSpaces.ReplaceAllString(html.UnescapeString(m[4]), " "))
		send, recv := strings.Contains(cls, "transmit"), strings.Contains(cls, "receive")
		if !send && !recv {
			continue
		}
		if marker == "" {
			if len(out) > 0 {
				out[len(out)-1].more = append(out[len(out)-1].more, text)
			}
			continue
		}
		layer := strings.Trim(marker, "-<>")
		if len(layer) != 1 {
			t.Fatalf("%s: marker %q", local, marker)
		}
		out = append(out, logEntry{send: send, layer: layer[0], text: text})
	}
	return out
}

func (e logEntry) octets(t *testing.T) []byte {
	t.Helper()
	var out []byte
	for _, line := range append([]string{e.text}, e.more...) {
		b, err := hex.DecodeString(strings.ReplaceAll(line, " ", ""))
		if err != nil {
			t.Fatalf("P row %q: %v", line, err)
		}
		out = append(out, b...)
	}
	return out
}

// logLink renders a frame as the runner's L rows do.
func logLink(f link.Frame) string {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	fcv := f.FCV
	if !f.Function.Primary() {
		fcv = f.DFC // the runner prints the DFC bit as fcv of a secondary frame
	}
	return fmt.Sprintf("master: %d pri: %d fcb: %d fcv: %d func: %s(0x%02X) 0x%02X length: %d dest: %d src: %d",
		b(f.Dir), b(f.Function.Primary()), b(f.FCB), b(fcv), "%s", uint8(f.Function)&0x0F, f.Control(), 5+len(f.Data), f.Dest, f.Src)
}

var logFuncName = regexp.MustCompile(`func: [A-Z_]+\(`)

// logTransport renders a transport header as the T rows do.
func logTransport(h transport.Header) string {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return fmt.Sprintf("fir: %d fin: %d seq: %d", b(h.FIR()), b(h.FIN()), h.Seq())
}

var logIIN = map[string]app.IIN{
	"Broadcast": app.IINBroadcast, "Class1Events": app.IINClass1Events, "Class2Events": app.IINClass2Events,
	"Class3Events": app.IINClass3Events, "NeedTime": app.IINNeedTime, "LocalControl": app.IINLocalControl,
	"DeviceTrouble": app.IINDeviceTrouble, "DeviceRestart": app.IINDeviceRestart,
	"FuncNotSupported": app.IINNoFuncCodeSupport, "ObjectUnknown": app.IINObjectUnknown,
	"ParamError": app.IINParameterError, "EventBufferOverflow": app.IINEventBufferOverflow,
	"AlreadyExecuting": app.IINAlreadyExecuting, "ConfigCorrupt": app.IINConfigCorrupt,
	"Reserved1": app.IINReserved1, "Reserved2": app.IINReserved2,
}

var logHeaderRow = regexp.MustCompile(`^g[0-9]+v[0-9]+, `)

var logApp = regexp.MustCompile(`^[A-Za-z ]+\(0x([0-9A-F]{2})\) fir: ([01]) fin: ([01]) con: ([01]) uns: ([01]) seq: 0x([0-9A-F]{2})(?: IIN\((.*)\))?$`)

// logHeader renders an object header as the runner's A detail rows do.
func logHeader(h app.Header) string {
	gv := fmt.Sprintf("g%dv%d", h.GV.Group(), h.GV.Variation())
	width := map[app.Qualifier]int{0x00: 1, 0x01: 2, 0x02: 4, 0x07: 1, 0x08: 2, 0x09: 4, 0x17: 1, 0x28: 2, 0x39: 4}[h.Qualifier]
	switch q := h.Qualifier; {
	case q == app.QualAll:
		return gv + ", All Objects"
	case q.IsRange():
		start, stop := h.Start, h.Stop
		if len(h.Objects) > 0 {
			start, stop = h.Objects[0].Index, h.Objects[len(h.Objects)-1].Index
		}
		return fmt.Sprintf("%s, %d-Byte Start/Stop, start: %d stop: %d", gv, width, start, stop)
	case q.IsIndexed():
		n := h.Count
		if len(h.Objects) > 0 {
			n = uint32(len(h.Objects))
		}
		return fmt.Sprintf("%s, %d-Byte Count and Index, count: %d", gv, width, n)
	default:
		n := h.Count
		if len(h.Objects) > 0 {
			n = uint32(len(h.Objects))
		}
		return fmt.Sprintf("%s, %d-Byte Count, count: %d", gv, width, n)
	}
}

// logValues renders the objects of a header as the runner's value rows
// ("[index] - ..."); ok is false for a kind of object the runner's rows
// were not seen for. cto is the fragment's last common time of occurrence.
func logValues(h app.Header, cto *app.Timestamp) (rows []string, ok bool) {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	for _, o := range h.Objects {
		var s string
		switch v := o.Value.(type) {
		case nil:
			return nil, false
		case app.CTO:
			*cto = v.Time
			rows = append(rows, fmt.Sprintf("time: %d", uint64(v.Time)))
			continue
		case app.AbsoluteTime:
			if h.GV != app.GV(50, 1) {
				return nil, false
			}
			rows = append(rows, fmt.Sprintf("time: %d", uint64(v.Time)))
			continue
		case app.TimeDelay:
			rows = append(rows, fmt.Sprintf("delay: %d", v.Delay.Milliseconds()))
			continue
		case app.Binary:
			fl := uint8(v.Flags)
			if v.Value {
				fl |= 0x80
			}
			if h.GV.Group() == 80 {
				s = fmt.Sprintf("BooleanValue(%v)", v.Value)
			} else {
				s = fmt.Sprintf("flags: 0x%02X", fl) + logTime(h.GV, v.Time, *cto)
			}
		case app.DoubleBitBinary:
			s = fmt.Sprintf("flags: 0x%02X", uint8(v.Flags)|uint8(v.Value)<<6) + logTime(h.GV, v.Time, *cto)
		case app.Counter:
			s = fmt.Sprintf("flags: 0x%02X count: %d", uint8(v.Flags), v.Value)
		case app.Analog:
			s = fmt.Sprintf("flags: 0x%02X value: %s", uint8(v.Flags), f(v.Value))
		case app.CROB:
			s = fmt.Sprintf("code: %d count: %d onTime: %d offTime: %d status: %d", v.Code(), v.Count, v.OnTime, v.OffTime, v.Status)
		case app.AnalogOutput:
			s = fmt.Sprintf("value: %s status: %d", f(v.Value), v.Status)
		default:
			return nil, false
		}
		rows = append(rows, fmt.Sprintf("[%d] - %s", o.Index, s))
	}
	return rows, true
}

// logTime renders the time of a binary or double-bit event variation:
// absolute (v2) or relative to the CTO (v3).
func logTime(gv app.GroupVariation, t, cto app.Timestamp) string {
	if g := gv.Group(); g != 2 && g != 4 {
		return ""
	}
	switch gv.Variation() {
	case 2:
		return fmt.Sprintf(" time: %d", uint64(t))
	case 3:
		return fmt.Sprintf(" cto: %d", uint64(t-cto))
	}
	return ""
}

// streamBytes concatenates the reassembled bytes of one direction of all
// conversations.
func streamBytes(r Recording, fromClient bool) []byte {
	var out []byte
	for _, s := range r.Conversations {
		for _, run := range s.Runs {
			if run.FromClient == fromClient {
				out = append(out, run.Data...)
			}
		}
	}
	return out
}

// logRefused are the procedures whose frames the runner damages on purpose
// and decodes leniently, and the number of their L rows go-dnp3's link
// decoder refuses (link.Decode, IEEE 1815-2012 clause 9.2.4.1): a primary
// function code the standard does not define (6.6.2.2: 5 and 10), user data
// in a frame whose length octet is 5 (6.6.2.3; the runner sends a READ with
// length 5 and the data block after it), and user data on RESET_LINK_STATES,
// TEST_LINK_STATES and REQUEST_LINK_STATUS (6.6.2.5).
var logRefused = map[string]int{"6.6.2.2": 2, "6.6.2.3": 2, "6.6.2.5": 3}

// logCrafted are the procedures that send hand-made frames without logging
// their application layer (no A rows) although they carry a fragment
// go-dnp3 reassembles: 6.6.2.5 sends a READ in CONFIRMED_USER_DATA with
// FCV 0 and in UNCONFIRMED_USER_DATA with FCV 1.
var logCrafted = map[string]bool{"6.6.2.5": true}

func TestConformanceLog(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	var files, pBlocks, lRows, tRows, aRows, hRows, vRows int
	for _, r := range recs {
		if r.File.Log == "" {
			continue
		}
		files++
		t.Run(r.File.ID, func(t *testing.T) {
			log := readLog(t, r.File.Log)
			refused := 0
			// P: the octets each side sent are the capture's streams.
			logged := map[bool]bool{}
			for _, e := range log {
				logged[e.send] = true
			}
			for _, send := range []bool{true, false} {
				if !logged[send] {
					// The procedure did not read what the outstation
					// sent (8.2.5.2.x: operate and check by hand): the
					// log has no rows of that direction.
					continue
				}
				var want []byte
				for _, e := range log {
					if e.layer == 'P' && e.send == send {
						want = append(want, e.octets(t)...)
						pBlocks++
					}
				}
				if got := streamBytes(r, send); !slices.Equal(got, want) {
					t.Errorf("runner sent=%v: capture stream %d octets, log %d octets\n capture % x\n log     % x", send, len(got), len(want), got, want)
				}
			}
			// L and T: each P block's frame, decoded by go-dnp3, against
			// the runner's decoding of the same block.
			for i, e := range log {
				if e.layer != 'P' {
					continue
				}
				// The runner logs L and T before P when sending, after P
				// when receiving.
				var lRow, tRow *logEntry
				if e.send {
					if i >= 1 && log[i-1].layer == 'L' && log[i-1].send {
						lRow = &log[i-1]
						if i >= 2 && log[i-2].layer == 'T' && log[i-2].send {
							tRow = &log[i-2]
						}
					}
				} else if i+1 < len(log) && log[i+1].layer == 'L' && !log[i+1].send {
					lRow = &log[i+1]
					if i+2 < len(log) && log[i+2].layer == 'T' && !log[i+2].send {
						tRow = &log[i+2]
					}
				}
				f, _, err := link.Decode(e.octets(t))
				if lRow == nil {
					continue // a frame the procedure damaged on purpose: no L row
				}
				lRows++
				if err != nil {
					refused++
					t.Logf("P %q: refused, the runner decoded it as %q: %v", e.text, lRow.text, err)
					continue
				}
				want := logFuncName.ReplaceAllString(lRow.text, "func: %s(")
				if got := logLink(f); got != want {
					t.Errorf("L: go-dnp3 %q, runner %q", got, want)
				}
				if tRow != nil {
					tRows++
					if got := logTransport(transport.Header(f.Data[0])); got != tRow.text {
						t.Errorf("T: go-dnp3 %q, runner %q", got, tRow.text)
					}
				}
			}
			if want := logRefused[r.File.Procedure]; refused != want {
				t.Errorf("go-dnp3 refused %d frames the runner decoded, want %d", refused, want)
			}
			// A: the fragments of each direction in order.
			for _, send := range []bool{true, false} {
				var ours []Fragment
				for _, s := range r.Conversations {
					for _, f := range s.Fragments {
						if f.FromClient == send {
							ours = append(ours, f)
						}
					}
				}
				if !logged[send] || (send && logCrafted[r.File.Procedure]) {
					continue
				}
				var rows []logEntry
				for _, e := range log {
					if e.layer == 'A' && e.send == send {
						rows = append(rows, e)
					}
				}
				if len(rows) != len(ours) {
					t.Errorf("runner sent=%v: %d A rows, go-dnp3 reassembled %d fragments", send, len(rows), len(ours))
					continue
				}
				for i, e := range rows {
					aRows++
					m := logApp.FindStringSubmatch(e.text)
					if m == nil {
						t.Fatalf("A row %q", e.text)
					}
					f := ours[i].Frag
					if f == nil {
						t.Errorf("A %q: no fragment header", e.text)
						continue
					}
					fc, _ := strconv.ParseUint(m[1], 16, 8)
					seq, _ := strconv.ParseUint(m[6], 16, 8)
					seq &= 0x0F // the runner prints the sequence number it was asked for (8.9.2.2: 0x29); the octet carries four bits
					c := f.Control
					got := fmt.Sprintf("fc=%d fir=%v fin=%v con=%v uns=%v seq=%d", f.Function, c.FIR, c.FIN, c.CON, c.UNS, c.Seq)
					want := fmt.Sprintf("fc=%d fir=%v fin=%v con=%v uns=%v seq=%d", fc, m[2] == "1", m[3] == "1", m[4] == "1", m[5] == "1", seq)
					if got != want {
						t.Errorf("A %q: go-dnp3 %s, runner %s", e.text, got, want)
					}
					var iin app.IIN
					if m[7] != "" {
						for _, name := range strings.Split(m[7], ", ") {
							bit, ok := logIIN[name]
							if !ok {
								t.Fatalf("IIN name %q", name)
							}
							iin |= bit
						}
					}
					if f.Function.IsResponse() && f.IIN != iin {
						t.Errorf("A %q: go-dnp3 IIN %s, runner %s", e.text, f.IIN, iin)
					}
					if ours[i].Err != nil {
						// The runner names the headers it sent; go-dnp3
						// refuses the fragment (the anomalies test
						// classifies why).
						continue
					}
					// The runner's detail rows: each header, then its
					// values. Values of kinds without a rendering here are
					// compared by count only.
					type group struct {
						header string
						values []string
					}
					var theirs []group
					for _, row := range e.more {
						if !logHeaderRow.MatchString(row) && len(theirs) > 0 {
							theirs[len(theirs)-1].values = append(theirs[len(theirs)-1].values, row)
						} else {
							theirs = append(theirs, group{header: row})
						}
					}
					if len(theirs) != len(f.Headers) {
						t.Errorf("A %q: go-dnp3 %d headers %v, runner %d %q", e.text, len(f.Headers), f.Headers, len(theirs), e.more)
						continue
					}
					var cto app.Timestamp
					for j, h := range f.Headers {
						hRows++
						if got := logHeader(h); got != theirs[j].header {
							t.Errorf("A %q header %d: go-dnp3 %q, runner %q", e.text, j, got, theirs[j].header)
						}
						vs, ok := logValues(h, &cto)
						if !ok {
							continue
						}
						vRows += len(vs)
						if !slices.Equal(vs, theirs[j].values) {
							t.Errorf("A %q header %d values: go-dnp3 %q, runner %q", e.text, j, vs, theirs[j].values)
						}
					}
				}
			}
		})
	}
	t.Logf("%d logs: %d P blocks, %d L rows, %d T rows, %d A rows, %d header and value rows checked (%d values)", files, pBlocks, lRows, tRows, aRows, hRows, vRows)
}
