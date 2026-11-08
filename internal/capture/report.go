// SPDX-License-Identifier: MIT

package capture

import (
	"fmt"
	"sort"

	"github.com/otfabric/go-dnp3/app"
)

// Report is testdata/captures/coverage.json: per file, what go-dnp3's
// codecs found in it.
type Report struct {
	Schema int          `json:"schema"`
	Totals Totals       `json:"totals"`
	Files  []FileReport `json:"files"`
}

// Totals sums the file reports.
type Totals struct {
	Files      int `json:"files"`
	Packets    int `json:"packets"`
	LinkFrames int `json:"link_frames"`
	Framing    int `json:"framing_errors"`
	Fragments  int `json:"fragments"`
	Decoded    int `json:"fragments_decoded"`
	Anomalies  int `json:"anomalies"`
}

// FileReport is the coverage of one file.
type FileReport struct {
	ID            string `json:"id"`
	Packets       int    `json:"packets"`
	Conversations int    `json:"conversations"`
	// LinkFrames counts the frames decoded, by "PRI|SEC function".
	LinkFrames map[string]int `json:"link_frames"`
	// Framing counts link.Reader's framing errors (skipped octets,
	// damaged frames); Cut the frames cut by a gap or the end of the
	// capture.
	Framing int `json:"framing_errors"`
	Cut     int `json:"cut"`
	// Fragments counts the reassembled fragments by function; Decoded
	// those app.Decode accepted.
	Fragments map[string]int `json:"fragments"`
	Decoded   int            `json:"fragments_decoded"`
	// MultiSegment counts fragments of more than one transport segment;
	// MultiFragment response fragments without FIN.
	MultiSegment  int `json:"multi_segment"`
	MultiFragment int `json:"multi_fragment"`
	// Objects are the object headers seen: "FUNCTION gXvY q=0xNN".
	Objects []string `json:"objects"`
	// IIN are the internal indications set in any response.
	IIN []string `json:"iin"`
	// Anomalies are the framing, transport and application errors.
	Anomalies []Anomaly `json:"anomalies"`
}

// Anomaly is one error found in a file.
type Anomaly struct {
	Frame int    `json:"frame"`
	Layer string `json:"layer"` // link, transport, application
	Error string `json:"error"`
}

// Anomalies returns the anomalies of a recording in a stable order.
func (r Recording) Anomalies() []Anomaly {
	var out []Anomaly
	for _, s := range r.Conversations {
		for _, lf := range s.Links {
			if lf.Err != nil {
				out = append(out, Anomaly{Frame: lf.Frame, Layer: "link", Error: lf.Err.Error()})
			}
		}
		for _, e := range s.Transport {
			out = append(out, Anomaly{Frame: e.Frame, Layer: "transport", Error: e.Err.Error()})
		}
		for _, f := range s.Fragments {
			if f.Err != nil {
				out = append(out, Anomaly{Frame: f.Frame, Layer: "application", Error: f.Err.Error()})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Frame < out[j].Frame })
	return out
}

// Coverage returns the report of a recording.
func (r Recording) Coverage() FileReport {
	fr := FileReport{ID: r.File.ID, Packets: r.Packets, Conversations: len(r.Conversations),
		LinkFrames: map[string]int{}, Fragments: map[string]int{}, Objects: []string{}, IIN: []string{},
		Anomalies: r.Anomalies()}
	if fr.Anomalies == nil {
		fr.Anomalies = []Anomaly{}
	}
	objs, iins := map[string]bool{}, map[string]bool{}
	for _, s := range r.Conversations {
		for _, lf := range s.Links {
			switch {
			case lf.Cut:
				fr.Cut++
			case lf.Err != nil:
				fr.Framing++
			default:
				kind := "SEC "
				if lf.Link.Function.Primary() {
					kind = "PRI "
				}
				fr.LinkFrames[kind+lf.Link.Function.String()]++
			}
		}
		for _, f := range s.Fragments {
			if f.Segments > 1 {
				fr.MultiSegment++
			}
			if f.Frag == nil {
				fr.Fragments["(short)"]++
				continue
			}
			fr.Fragments[f.Frag.Function.String()]++
			if f.Err != nil {
				continue
			}
			fr.Decoded++
			if f.Frag.Function.IsResponse() {
				if !f.Frag.Control.FIN {
					fr.MultiFragment++
				}
				for b := range 16 {
					if bit := app.IIN(1) << b; f.Frag.IIN&bit != 0 {
						iins[bit.String()] = true
					}
				}
			}
			for _, h := range f.Frag.Headers {
				objs[fmt.Sprintf("%s %s q=0x%02X", f.Frag.Function, h.GV, uint8(h.Qualifier))] = true
			}
		}
	}
	for k := range objs {
		fr.Objects = append(fr.Objects, k)
	}
	for k := range iins {
		fr.IIN = append(fr.IIN, k)
	}
	sort.Strings(fr.Objects)
	sort.Strings(fr.IIN)
	return fr
}

// BuildReport returns the report of the corpus.
func BuildReport(recs []Recording) Report {
	rep := Report{Schema: 1}
	for _, r := range recs {
		fr := r.Coverage()
		rep.Files = append(rep.Files, fr)
		rep.Totals.Files++
		rep.Totals.Packets += fr.Packets
		for _, n := range fr.LinkFrames {
			rep.Totals.LinkFrames += n
		}
		rep.Totals.Framing += fr.Framing
		for _, n := range fr.Fragments {
			rep.Totals.Fragments += n
		}
		rep.Totals.Decoded += fr.Decoded
		rep.Totals.Anomalies += len(fr.Anomalies)
	}
	return rep
}
