// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/otfabric/go-dnp3/link"
)

// Manifest is testdata/captures/manifest.json: the sources of the recorded
// traffic and, per file, where it came from, its checksum and its evidence
// class.
type Manifest struct {
	Schema   int               `json:"schema"`
	Acquired string            `json:"acquired"`
	Classes  map[string]string `json:"classes"`
	Sources  []Source          `json:"sources"`
	Files    []File            `json:"files"`
	// Examined lists files of the sources that are not here, and why.
	Examined []Examined `json:"examined"`
}

// Examined is a file of a source that is not in the corpus.
type Examined struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Why    string `json:"why"`
}

// Source is one origin of captures.
type Source struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Revision       string `json:"revision"`
	Licence        string `json:"licence"`
	Redistribution string `json:"redistribution"`
	// UnknownOrigin marks a source whose origin is not known: a file
	// handed over without its provenance. It has no URL or revision, its
	// Licence says that the terms are unknown, and its files are of class
	// C or D only.
	UnknownOrigin bool `json:"unknown_origin,omitempty"`
}

// File is one capture file.
type File struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	// Name is the file's name here, <client-or-peer>_<device>_<operation>
	// with the original extension (testdata/captures/README.md).
	Name         string `json:"name"`
	OriginalName string `json:"original_name"`
	Path         string `json:"path"` // in the source
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Recorded     string `json:"recorded"`
	// Class is the evidence class (see Manifest.Classes).
	Class string `json:"class"`
	// Storage is "raw": committed byte-identical at Local.
	Storage     string   `json:"storage"`
	Local       string   `json:"local"`
	Devices     []string `json:"devices"`
	Peers       []string `json:"peers"`
	Operations  []string `json:"operations"`
	Limitations string   `json:"limitations"`
	// Procedure, Verdict and Log are set for the conformance runner's
	// captures: the procedure of the DNP3 IED certification procedure, the
	// runner's verdict and its log (with the log's SHA256).
	Procedure string `json:"procedure,omitempty"`
	Verdict   string `json:"verdict,omitempty"`
	Log       string `json:"log,omitempty"`
	LogSHA256 string `json:"log_sha256,omitempty"`
}

// ReadManifest reads manifest.json from the captures directory dir.
func ReadManifest(dir string) (Manifest, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile("manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("capture: manifest: %w", err)
	}
	return m, nil
}

// Recording is one file of the corpus, read and run through go-dnp3's
// link, transport and application codecs.
type Recording struct {
	File          File
	Packets       int
	Conversations []Stream
}

// Stream is one conversation with its DNP3 layers.
type Stream struct {
	Conversation
	Links     []LinkFrame
	Fragments []Fragment
	Transport []TransportEvent
}

// Analyze runs the codecs over the conversations of one file. A
// conversation without the DNP3 start octets anywhere (other TCP or UDP
// traffic) is left out.
func Analyze(convs []Conversation) []Stream {
	var out []Stream
	for _, c := range convs {
		ok := false
		for _, r := range c.Runs {
			if bytes.Contains(r.Data, []byte{link.Start0, link.Start1}) {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		lfs := LinkFrames(c)
		frags, evs := Fragments(lfs)
		out = append(out, Stream{Conversation: c, Links: lfs, Fragments: frags, Transport: evs})
	}
	return out
}

// Load reads every capture of the corpus in the captures directory dir.
func Load(dir string) ([]Recording, error) {
	m, err := ReadManifest(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Recording, 0, len(m.Files))
	for _, f := range m.Files {
		convs, n, err := ReadFile(filepath.Join(dir, f.Local))
		if err != nil {
			return nil, fmt.Errorf("capture: %s: %w", f.ID, err)
		}
		out = append(out, Recording{File: f, Packets: n, Conversations: Analyze(convs)})
	}
	return out, nil
}

var (
	cacheMu sync.Mutex
	cache   = map[string][]Recording{}
)

// Cached is Load, read once per directory and process. The recordings
// must not be modified.
func Cached(dir string) ([]Recording, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if r, ok := cache[dir]; ok {
		return r, nil
	}
	r, err := Load(dir)
	if err == nil {
		cache[dir] = r
	}
	return r, err
}

// Get returns the recording of the file with manifest ID id.
func Get(recs []Recording, id string) (Recording, bool) {
	for _, r := range recs {
		if r.File.ID == id {
			return r, true
		}
	}
	return Recording{}, false
}
