// SPDX-License-Identifier: MIT

package capture

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/otfabric/go-dnp3/app"
	"github.com/otfabric/go-dnp3/link"
)

const capturesDir = "../../testdata/captures"

// openRoot opens dir as an os.Root for the duration of the test: the
// tests read and write the files of the corpus through it, so that a
// name from the manifest cannot reach outside dir.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// TestManifest: the manifest names every file of the corpus with its
// source and class; the committed files have the manifest's SHA256 and
// size; SHA256SUMS covers every committed file, the conformance runner's
// logs included.
func TestManifest(t *testing.T) {
	m, err := ReadManifest(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]bool{}
	unknown := map[string]bool{}
	for _, s := range m.Sources {
		sources[s.ID] = true
		switch {
		case s.Licence == "" || s.Redistribution == "":
			t.Errorf("source %s: licence or redistribution missing", s.ID)
		case s.UnknownOrigin:
			// No URL or revision to give; the files must say where they
			// were found as far as known (limitations) and stay C or D.
			unknown[s.ID] = true
			if s.URL != "" || s.Revision != "" {
				t.Errorf("source %s: unknown origin with a URL or revision", s.ID)
			}
		case s.URL == "" || len(s.Revision) != 40:
			t.Errorf("source %s: URL or revision missing", s.ID)
		}
	}
	sums := readSums(t)
	seen := map[string]bool{}
	check := func(local, want string, size int64) {
		b, err := os.ReadFile(filepath.Join(capturesDir, filepath.FromSlash(local)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		got := hex.EncodeToString(sum[:])
		if sums[local] != got || got != want || (size >= 0 && int64(len(b)) != size) {
			t.Errorf("%s: SHA256SUMS %q, manifest %q, file %s", local, sums[local], want, got)
		}
		delete(sums, local)
	}
	for _, f := range m.Files {
		if seen[f.ID] || !sources[f.Source] || m.Classes[f.Class] == "" || (f.URL == "") != unknown[f.Source] || len(f.Operations) == 0 ||
			!cleanName.MatchString(f.Name) || f.OriginalName != filepath.Base(f.Path) || filepath.Ext(f.Name) != filepath.Ext(f.OriginalName) ||
			f.Storage != "raw" || f.Limitations == "" {
			t.Errorf("file %s: duplicate, or source %q, class %q, URL, operations, name or limitations wrong", f.ID, f.Source, f.Class)
		}
		seen[f.ID] = true
		if filepath.Base(f.Local) != f.Name || filepath.ToSlash(filepath.Dir(f.Local)) != f.Source {
			t.Errorf("%s: stored as %s, named %s", f.ID, f.Local, f.Name)
		}
		if f.Class == "A" || f.Class == "B" {
			t.Errorf("%s: class %s needs identified hardware; none of the sources documents it", f.ID, f.Class)
		}
		if unknown[f.Source] && f.Class != "C" && f.Class != "D" {
			t.Errorf("%s: a file of unknown origin is of class C or D, not %s", f.ID, f.Class)
		}
		check(f.Local, f.SHA256, f.Size)
		if f.Log != "" {
			if f.Log != strings.TrimSuffix(f.Local, ".pcap")+".log.html" {
				t.Errorf("%s: log %s", f.ID, f.Log)
			}
			check(f.Log, f.LogSHA256, -1)
		}
	}
	for p := range sums {
		t.Errorf("SHA256SUMS: %s is not in the manifest", p)
	}
	// Every capture file in the source directories is in the manifest.
	for s := range sources {
		ents, err := os.ReadDir(filepath.Join(capturesDir, s))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			name := e.Name()
			if strings.HasSuffix(name, ".log.html") {
				continue
			}
			found := false
			for _, f := range m.Files {
				found = found || f.Local == s+"/"+name
			}
			if !found {
				t.Errorf("%s/%s is not in the manifest", s, name)
			}
		}
	}
}

// cleanName is <client-or-peer>_<device>_<operation>.<ext>: lower case,
// words joined by hyphens.
var cleanName = regexp.MustCompile(`^[a-z0-9.-]+_[a-z0-9.-]+_[a-z0-9-]+\.(pcap|pcapng)$`)

func readSums(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(capturesDir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, path, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("SHA256SUMS: %q", sc.Text())
		}
		out[path] = sum
	}
	return out
}

// TestCoverage: the codecs' findings in every file are those of
// testdata/captures/coverage.json. DNP3_CAPTURE_UPDATE=1 rewrites it;
// a change must then be explained in the commit.
func TestCoverage(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(BuildReport(recs), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	captures := openRoot(t, capturesDir)
	if os.Getenv("DNP3_CAPTURE_UPDATE") != "" {
		if err := captures.WriteFile("coverage.json", got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := captures.ReadFile("coverage.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("coverage.json is not what the codecs find; run DNP3_CAPTURE_UPDATE=1 go test ./internal/capture and review the difference")
	}
}

// TestRoundTrip: every frame link.Reader decoded encodes back to its
// recorded octets, and every fragment app.Decode accepted encodes back to
// its reassembled octets: both encodings are canonical for what the
// recordings hold.
func TestRoundTrip(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	var frames, frags int
	for _, r := range recs {
		for _, s := range r.Conversations {
			for _, lf := range s.Links {
				if lf.Err != nil {
					continue
				}
				frames++
				b, err := lf.Link.Encode()
				if err != nil || !bytes.Equal(b, lf.Raw) {
					t.Errorf("%s frame %d: %s encodes to % x (%v), recorded % x", r.File.ID, lf.Frame, &lf.Link, b, err, lf.Raw)
				}
				if d, n, err := link.Decode(lf.Raw); err != nil || n != len(lf.Raw) || d.Control() != lf.Link.Control() {
					t.Errorf("%s frame %d: link.Decode %v", r.File.ID, lf.Frame, err)
				}
			}
			for _, f := range s.Fragments {
				if f.Err != nil {
					continue
				}
				frags++
				b, err := f.Frag.Encode()
				if err != nil || !bytes.Equal(b, f.Raw) {
					t.Errorf("%s frame %d: %s encodes to % x (%v), recorded % x", r.File.ID, f.Frame, f.Frag, b, err, f.Raw)
				}
			}
		}
	}
	t.Logf("%d link frames and %d fragments encode back to the recorded octets", frames, frags)
}

// anomalyClass classifies an anomaly: the error must contain match, in a
// file whose ID has the prefix.
type anomalyClass struct {
	file, layer, match string
	category, why      string
}

// anomalyClasses are the classifications of every framing, transport and
// application error found in the corpus (coverage.json lists them by
// frame).
var anomalyClasses = []anomalyClass{
	{"test-data-part", "link", "invalid start octets", "legitimate refusal",
		"deliberately damaged frame (start octets 05 05): skipped as IEEE 1815-2012 clause 9.2.6 requires; tshark finds no frame there either"},
	{"zeek-test-data-merged", "link", "invalid start octets", "legitimate refusal", "the same damaged frame as test-data-part1"},
	{"test-data-part", "application", "invalid qualifier: 0xED", "legitimate refusal",
		"a header with qualifier 0xED, which IEEE 1815-2012 clause 4.4.4 does not define (tshark: \"Unknown Range Type\")"},
	{"zeek-test-data-merged", "application", "invalid qualifier: 0xED", "legitimate refusal", "the same fragments as test-data-part1"},
	{"direct-operate-crob-malform-but-good-crc", "application", "truncated g12v1", "legitimate refusal",
		"the file's purpose: a g12v1 header that announces 2 objects with 13 octets after it (11 per object)"},
	{"conformance-6-6-2-1", "link", "invalid start octets", "legitimate refusal", "procedure 6.6.2.1 sends invalid start octets"},
	{"conformance-6-6-2-2", "link", "invalid function code", "legitimate refusal", "procedure 6.6.2.2 sends primary function codes 5 and 10, which IEEE 1815-2012 clause 9.2.4.1.3 does not define"},
	{"conformance-6-6-2-3", "link", "", "legitimate refusal",
		"procedure 6.6.2.3 sends a READ whose length octet is 5 with a data block after it: no user data for UNCONFIRMED_USER_DATA, and the 14 octets after it are skipped"},
	{"conformance-6-6-2-4", "link", "", "legitimate refusal",
		"procedure 6.6.2.4 sends frames with a damaged header CRC, and (like 6.6.2.3) with length octet 5 and a data block after it"},
	{"conformance-6-6-2-5", "link", "with 15 octets of user data", "legitimate refusal",
		"procedure 6.6.2.5 sends RESET_LINK_STATES, TEST_LINK_STATES and REQUEST_LINK_STATUS with user data; IEEE 1815-2012 clause 9.2.4.1.3 gives them none"},
	{"conformance-8-6-2-2", "application", "unknown function code: 112", "legitimate refusal",
		"procedure 8.6.2.2 sends function code 112 to see IIN2.0; app.Decode returns the header with ErrUnknownFunction so that the outstation can answer"},
	{"igbe-ddca-smart-grid-attacks", "link", "3 octets skipped", "legitimate refusal",
		"three octets of an injected segment of the attack scenario between frames: skipped, the next frame is found (the resynchronisation of IEEE 1815-2012 clause 9.2.6)"},
}

// TestAnomalies: every error the codecs report in the corpus is
// classified.
func TestAnomalies(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	used := make([]bool, len(anomalyClasses))
	n := 0
	for _, r := range recs {
		for _, a := range r.Anomalies() {
			n++
			found := false
			for i, c := range anomalyClasses {
				if strings.HasPrefix(r.File.ID, c.file) && a.Layer == c.layer && strings.Contains(a.Error, c.match) {
					found, used[i] = true, true
					break
				}
			}
			if !found {
				t.Errorf("%s frame %d: unclassified %s error: %s", r.File.ID, a.Frame, a.Layer, a.Error)
			}
		}
	}
	for i, u := range used {
		if !u {
			t.Errorf("classification %+v matches nothing", anomalyClasses[i])
		}
	}
	t.Logf("%d anomalies, all classified", n)
}

// TestTransport: the transport function reassembled every fragment the
// recordings hold; no segment was refused.
func TestTransport(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	var multi int
	for _, r := range recs {
		for _, s := range r.Conversations {
			for _, e := range s.Transport {
				t.Errorf("%s frame %d: %v", r.File.ID, e.Frame, e.Err)
			}
			for _, f := range s.Fragments {
				if f.Segments > 1 {
					multi++
				}
			}
		}
	}
	if multi == 0 {
		t.Error("no fragment of several segments in the corpus")
	}
	t.Logf("%d fragments of several transport segments", multi)
}

// TestFunctionsSeen: the corpus exercises the functions the docs claim it
// does (testdata/captures/README.md).
func TestFunctionsSeen(t *testing.T) {
	recs, err := Cached(capturesDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[app.FunctionCode]int{}
	groups := map[uint8]int{}
	for _, r := range recs {
		for _, s := range r.Conversations {
			for _, f := range s.Fragments {
				if f.Frag == nil || f.Err != nil {
					continue
				}
				seen[f.Frag.Function]++
				for _, h := range f.Frag.Headers {
					groups[h.GV.Group()]++
				}
			}
		}
	}
	for _, fc := range []app.FunctionCode{app.FuncConfirm, app.FuncRead, app.FuncWrite, app.FuncSelect, app.FuncOperate,
		app.FuncDirectOperate, app.FuncDirectOperateNoAck, app.FuncImmediateFreeze, app.FuncColdRestart, app.FuncWarmRestart,
		app.FuncEnableUnsolicited, app.FuncDisableUnsolicited, app.FuncAssignClass, app.FuncDelayMeasure, app.FuncRecordCurrentTime,
		app.FuncOpenFile, app.FuncCloseFile, app.FuncDeleteFile, app.FuncAuthRequest, app.FuncResponse, app.FuncUnsolicitedResponse,
		app.FuncAuthResponse} {
		if seen[fc] == 0 {
			t.Errorf("no %s in the corpus", fc)
		}
	}
	for _, g := range []uint8{0, 1, 2, 10, 12, 20, 30, 32, 41, 50, 51, 52, 60, 70, 80, 85, 86, 112, 120} {
		if groups[g] == 0 {
			t.Errorf("no group %d in the corpus", g)
		}
	}
}
