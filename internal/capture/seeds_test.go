// SPDX-License-Identifier: MIT

package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestFuzzSeeds keeps the fuzz corpora of the codecs, the outstation and
// the master seeded with recorded traffic: one seed per distinct shape
// (function and object headers) of fragment, every fragment app.Decode
// refuses, one link frame per distinct control octet and the octets
// around every framing error. DNP3_CAPTURE_SEEDS=1 writes them into the
// packages' testdata/fuzz directories; without it, the test checks they
// are there.
func TestFuzzSeeds(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	seeds := map[string]map[string][]byte{} // dir -> name -> input
	add := func(dir, name string, b []byte) {
		if seeds[dir] == nil {
			seeds[dir] = map[string][]byte{}
		}
		seeds[dir][name] = b
	}
	shapes := map[string]bool{}
	ctls := map[byte]bool{}
	for _, r := range recs {
		for _, s := range r.Conversations {
			for _, lf := range s.Links {
				if lf.Err == nil && !ctls[lf.Raw[3]] {
					ctls[lf.Raw[3]] = true
					name := fmt.Sprintf("capture-%s-%d", r.File.ID, lf.Frame)
					add("link/testdata/fuzz/FuzzDecode", name, lf.Raw)
				}
			}
			for _, run := range s.Runs {
				// The octets of a run around each framing error, for the
				// Reader's resynchronisation.
				for _, lf := range s.Links {
					if lf.Err == nil || lf.FromClient != run.FromClient {
						continue
					}
					i := sort.SearchInts(run.Frames, lf.Frame)
					if i >= len(run.Frames) || run.Frames[i] != lf.Frame {
						continue
					}
					lo, hi := max(0, i-300), min(len(run.Data), i+300)
					add("link/testdata/fuzz/FuzzReader", fmt.Sprintf("capture-%s-%d", r.File.ID, lf.Frame), run.Data[lo:hi])
				}
			}
			for _, f := range s.Fragments {
				var sig strings.Builder
				if f.Frag != nil {
					fmt.Fprintf(&sig, "%s", f.Frag.Function)
					for _, h := range f.Frag.Headers {
						fmt.Fprintf(&sig, " %s/%s", h.GV, h.Qualifier)
					}
				}
				if f.Err == nil && shapes[sig.String()] {
					continue
				}
				shapes[sig.String()] = true
				name := fmt.Sprintf("capture-%s-%d", r.File.ID, f.Frame)
				add("app/testdata/fuzz/FuzzDecode", name, f.Raw)
				if f.Frag == nil {
					continue
				}
				switch {
				case !f.Frag.Function.IsResponse():
					add("server/testdata/fuzz/FuzzOutstation", name, f.Raw)
				case len(f.Raw) > 2 && len(f.Raw) <= 2048:
					add("client/testdata/fuzz/FuzzMaster", name, f.Raw[2:])
				}
			}
		}
	}
	update := os.Getenv("DNP3_CAPTURE_SEEDS") != ""
	n := 0
	for dir, files := range seeds {
		full := filepath.Join("..", "..", filepath.FromSlash(dir))
		if update {
			if err := os.MkdirAll(full, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		for name, b := range files {
			n++
			p := filepath.Join(full, name)
			want := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", b)
			if update {
				if err := os.WriteFile(p, []byte(want), 0o600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			got, err := os.ReadFile(p)
			if err != nil || string(got) != want {
				t.Errorf("%s: missing or changed; DNP3_CAPTURE_SEEDS=1 go test -run TestFuzzSeeds ./internal/capture writes it", p)
			}
		}
	}
	t.Logf("%d fuzz seeds from the captures", n)
}
