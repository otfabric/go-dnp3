// SPDX-License-Identifier: MIT

// Command upstreamwatch tells whether the upstreams go-dnp3 follows have
// moved, and whether they still agree with it:
//
//   - the object definitions of stepfunc dnp3 (its codegen model) and of
//     DSC go-dnp3 (its object YAML): a commit since the one recorded in
//     .github/upstream.json as reviewed, and the size of every object they
//     define with a fixed layout compared with app/catalog.json;
//   - otfabric/dnp3-interop: a release newer than the one the interop
//     harness pins.
//
// It reads the upstream files when it runs and keeps none of them: the
// comparison is of facts (group, variation, size). It prints a Markdown
// report; with -out it also writes it to a file, and with -github-output
// it writes attention=true|false for a workflow. Set GITHUB_TOKEN to raise
// the GitHub API limits.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// upstream is .github/upstream.json: the commits last reviewed.
type upstream struct {
	Sources []source `json:"sources"`
}

type source struct {
	Name string `json:"name"`
	Repo string `json:"repo"`
	// Path is the file or directory with the object definitions.
	Path   string `json:"path"`
	Format string `json:"format"` // "stepfunc" or "dsc"
	// Reviewed is the commit whose definitions were last compared and
	// accepted.
	Reviewed string `json:"reviewed"`
}

type catalog struct {
	Objects []struct {
		Group     uint8 `json:"group"`
		Variation uint8 `json:"variation"`
		Size      *int  `json:"size"`
	} `json:"objects"`
}

type key struct{ g, v int }

func main() {
	out := flag.String("out", "", "also write the report to this file")
	ghOut := flag.String("github-output", "", "append attention=true|false to this file (GITHUB_OUTPUT)")
	flag.Parse()
	report, attention, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "upstreamwatch:", err)
		os.Exit(1)
	}
	fmt.Print(report)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "upstreamwatch:", err)
			os.Exit(1)
		}
	}
	if *ghOut != "" {
		f, err := os.OpenFile(*ghOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = fmt.Fprintf(f, "attention=%v\n", attention)
			_ = f.Close()
		}
	}
}

func run() (string, bool, error) {
	var up upstream
	if err := readJSON(".github/upstream.json", &up); err != nil {
		return "", false, err
	}
	var cat catalog
	if err := readJSON("app/catalog.json", &cat); err != nil {
		return "", false, err
	}
	ours := map[key]*int{}
	for _, o := range cat.Objects {
		ours[key{int(o.Group), int(o.Variation)}] = o.Size
	}
	var w strings.Builder
	attention := false
	w.WriteString("# Upstream watch\n\n")
	fmt.Fprintf(&w, "Run of %s.\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))

	for _, s := range up.Sources {
		head, err := latestCommit(s.Repo, s.Path)
		if err != nil {
			return "", false, fmt.Errorf("%s: %w", s.Name, err)
		}
		fmt.Fprintf(&w, "## %s\n\n", s.Name)
		if head == s.Reviewed {
			fmt.Fprintf(&w, "Unchanged since the reviewed commit %s.\n\n", short(s.Reviewed))
		} else {
			attention = true
			fmt.Fprintf(&w, "**Changed**: `%s` has commits since the reviewed %s: [compare %s...%s](https://github.com/%s/compare/%s...%s). Review them, update `app/catalog.json` if the standard's objects are concerned, and set `reviewed` in `.github/upstream.json` to `%s`.\n\n",
				s.Path, short(s.Reviewed), short(s.Reviewed), short(head), s.Repo, s.Reviewed, head, head)
		}
		theirs, skipped, err := definitions(s, head)
		if err != nil {
			return "", false, fmt.Errorf("%s: %w", s.Name, err)
		}
		var differ, missing []string
		compared := 0
		for k, size := range theirs {
			mine, ok := ours[k]
			switch {
			case !ok:
				missing = append(missing, fmt.Sprintf("g%dv%d (%d octets)", k.g, k.v, size))
			case mine == nil:
				differ = append(differ, fmt.Sprintf("g%dv%d: %d octets there, not fixed here", k.g, k.v, size))
			case *mine != size:
				differ = append(differ, fmt.Sprintf("g%dv%d: %d octets there, %d here", k.g, k.v, size, *mine))
			default:
				compared++
			}
		}
		sort.Strings(differ)
		sort.Strings(missing)
		fmt.Fprintf(&w, "%d objects with a fixed layout agree with the catalog", compared)
		if skipped > 0 {
			fmt.Fprintf(&w, "; %d definitions without one were not compared", skipped)
		}
		w.WriteString(".\n\n")
		if len(differ) > 0 {
			attention = true
			w.WriteString("**Sizes that differ**:\n\n")
			for _, d := range differ {
				fmt.Fprintf(&w, "- %s\n", d)
			}
			w.WriteString("\n")
		}
		if len(missing) > 0 {
			attention = true
			w.WriteString("**Objects there that the catalog lacks**:\n\n")
			for _, m := range missing {
				fmt.Fprintf(&w, "- %s\n", m)
			}
			w.WriteString("\n")
		}
	}

	pinned, err := pinnedInterop()
	if err != nil {
		return "", false, err
	}
	latest, err := latestRelease("otfabric/dnp3-interop")
	if err != nil {
		return "", false, fmt.Errorf("dnp3-interop: %w", err)
	}
	w.WriteString("## otfabric/dnp3-interop\n\n")
	if latest == pinned {
		fmt.Fprintf(&w, "The interop harness pins the latest release, %s.\n", pinned)
	} else {
		attention = true
		fmt.Fprintf(&w, "**A newer release**: %s; the interop harness pins %s. Pin its image digests (interop/harness.go, Makefile, .github/workflows/interop.yml) and run make interop.\n", latest, pinned)
	}
	return w.String(), attention, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func get(url string, api bool) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if t := os.Getenv("GITHUB_TOKEN"); t != "" && api {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	if api {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return b, nil
}

func latestCommit(repo, path string) (string, error) {
	b, err := get(fmt.Sprintf("https://api.github.com/repos/%s/commits?path=%s&per_page=1", repo, path), true)
	if err != nil {
		return "", err
	}
	var cs []struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(b, &cs); err != nil || len(cs) == 0 {
		return "", fmt.Errorf("no commit for %s: %v", path, err)
	}
	return cs[0].SHA, nil
}

func latestRelease(repo string) (string, error) {
	b, err := get(fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo), true)
	if err != nil {
		return "", err
	}
	var r struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", err
	}
	return r.Tag, nil
}

var interopConst = regexp.MustCompile(`interopRelease\s*=\s*"([^"]+)"`)

// pinnedInterop is the dnp3-interop release the harness pins.
func pinnedInterop() (string, error) {
	b, err := os.ReadFile("interop/harness.go")
	if err != nil {
		return "", err
	}
	m := interopConst.FindSubmatch(b)
	if m == nil {
		return "", fmt.Errorf("interop/harness.go: no interopRelease")
	}
	return string(m[1]), nil
}

// definitions returns the size of every object the source defines with a
// fixed layout, at commit ref, and how many definitions it skipped.
func definitions(s source, ref string) (map[key]int, int, error) {
	switch s.Format {
	case "dsc":
		b, err := get(fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", s.Repo, ref, s.Path), false)
		if err != nil {
			return nil, 0, err
		}
		defs, skipped := parseDSC(string(b))
		return defs, skipped, nil
	case "stepfunc":
		b, err := get(fmt.Sprintf("https://api.github.com/repos/%s/contents/%s/groups?ref=%s", s.Repo, s.Path, ref), true)
		if err != nil {
			return nil, 0, err
		}
		var files []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(b, &files); err != nil {
			return nil, 0, err
		}
		defs, skipped := map[key]int{}, 0
		for _, f := range files {
			if !strings.HasSuffix(f.Name, ".scala") {
				continue
			}
			src, err := get(fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/groups/%s", s.Repo, ref, s.Path, f.Name), false)
			if err != nil {
				return nil, 0, err
			}
			d, n := parseStepfunc(string(src))
			for k, v := range d {
				defs[k] = v
			}
			skipped += n
		}
		return defs, skipped, nil
	default:
		return nil, 0, fmt.Errorf("unknown format %q", s.Format)
	}
}

// DSC go-dnp3's YAML: one flow mapping per object, field types with fixed
// widths; packed and variable objects have no fixed layout.
var (
	dscInt    = regexp.MustCompile(`\b(group|variation):\s*(\d+)`)
	dscType   = regexp.MustCompile(`type:\s*([a-z0-9]+)`)
	dscWidths = map[string]int{"flags": 1, "u8": 1, "status": 1, "i16": 2, "u16": 2, "i32": 4, "u32": 4, "f32": 4, "f64": 8, "time48": 6, "time16": 2}
)

func parseDSC(src string) (map[key]int, int) {
	defs, skipped := map[key]int{}, 0
	for _, entry := range dscEntries(src) {
		ints := map[string]int{}
		for _, m := range dscInt.FindAllStringSubmatch(entry, -1) {
			ints[m[1]], _ = strconv.Atoi(m[2])
		}
		if _, ok := ints["group"]; !ok {
			continue
		}
		k := key{ints["group"], ints["variation"]}
		if strings.Contains(entry, "packed:") || strings.Contains(entry, "variable: true") || !strings.Contains(entry, "fields:") {
			skipped++
			continue
		}
		size, ok := 0, true
		for _, m := range dscType.FindAllStringSubmatch(entry, -1) {
			w, known := dscWidths[m[1]]
			ok = ok && known
			size += w
		}
		if !ok || size == 0 {
			skipped++
			continue
		}
		defs[k] = size
	}
	return defs, skipped
}

// dscEntries splits the YAML into its "- {...}" objects, by braces.
func dscEntries(src string) []string {
	var out []string
	for i := 0; i < len(src); i++ {
		if src[i] != '{' || !strings.HasSuffix(strings.TrimRight(src[:i], " "), "-") {
			continue
		}
		depth, j := 0, i
		for ; j < len(src); j++ {
			if src[j] == '{' {
				depth++
			} else if src[j] == '}' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		out = append(out, src[i:min(j+1, len(src))])
		i = j
	}
	return out
}

// stepfunc dnp3's Scala model: "object GroupNVarM extends FixedSize(GroupN,
// M, ...)(field, field, ...)", the fields named or built inline.
var (
	sfObject = regexp.MustCompile(`object Group(\d+)Var(\d+) extends (\w+)\(`)
	sfFields = map[string]int{
		"flags": 1, "time16": 2, "time48": 6, "count16": 2, "count32": 4, "value16": 2, "value32": 4,
		"float32": 4, "float64": 8, "valueU16": 2, "valueU32": 4, "commandStatus": 1, "unsignedByte": 1,
	}
	sfTypes = map[string]int{
		"UInt8Field": 1, "UInt16Field": 2, "UInt32Field": 4, "S16Field": 2, "S32Field": 4,
		"Float32Field": 4, "Float64Field": 8, "TimestampField": 6, "EnumFieldType": 1, "CustomFieldTypeU8": 1,
	}
)

func parseStepfunc(src string) (map[key]int, int) {
	defs, skipped := map[key]int{}, 0
	for _, loc := range sfObject.FindAllStringSubmatchIndex(src, -1) {
		g, _ := strconv.Atoi(src[loc[2]:loc[3]])
		v, _ := strconv.Atoi(src[loc[4]:loc[5]])
		if src[loc[6]:loc[7]] != "FixedSize" {
			if v != 0 {
				skipped++
			}
			continue
		}
		_, rest := balanced(src[loc[1]-1:])
		rest = strings.TrimLeft(rest, " \t\n")
		if !strings.HasPrefix(rest, "(") {
			skipped++
			continue
		}
		fields, _ := balanced(rest)
		size, ok := 0, true
		for _, f := range splitTop(fields) {
			f = strings.TrimSpace(f)
			switch {
			case strings.HasPrefix(f, "FixedSizeField("):
				w := 0
				for t, n := range sfTypes {
					if strings.Contains(f, t) {
						w = n
					}
				}
				ok = ok && w > 0
				size += w
			default:
				w, known := sfFields[f]
				ok = ok && known
				size += w
			}
		}
		if !ok || size == 0 {
			skipped++
			continue
		}
		defs[key{g, v}] = size
	}
	return defs, skipped
}

// balanced returns the inside of the parenthesis s starts with, and what
// follows it.
func balanced(s string) (inside, rest string) {
	depth := 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i], s[i+1:]
			}
		}
	}
	return "", ""
}

// splitTop splits at the commas outside parentheses.
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(s[start:]) != "" {
		out = append(out, s[start:])
	}
	return out
}
