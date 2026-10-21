//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// adapter is one reference implementation, as a container image that follows
// the dnp3-interop container contract 1.3.
type adapter struct {
	name  string
	image string
}

// The reference images this version of go-dnp3 is qualified against:
// otfabric/dnp3-interop v0.4.3 (stepfunc dnp3 1.7.0, opendnp3 3.1.2, DSC
// go-dnp3 v0.8.1, dnp3py 0.6.0). The published images are pinned by
// multi-arch index digest so that a run is reproducible. The stepfunc
// image is not published, as Step Function I/O's licence does not allow
// redistributing its library: `make interop-stepfunc` builds it locally,
// under this tag, from dnp3-interop's source at the release's commit.
// Moving to another release of dnp3-interop means changing these
// constants; the Makefile and the interop workflow follow.
const (
	interopRelease         = "v0.4.3"
	defaultStepfuncImage   = "dnp3-interop-stepfunc:" + interopRelease
	defaultOpendnp3Image   = "ghcr.io/otfabric/dnp3-interop-opendnp3@sha256:d8d8dcc2ced9499853b5ece8fda709d935c23981f00e84241ceb2286075835b4"
	defaultDscsystemsImage = "ghcr.io/otfabric/dnp3-interop-dscsystems@sha256:f53f82430f60b6c40acd89928cab3aea675565ce0f96fe664b067ac9bfae93b9"
	defaultDnp3pyImage     = "ghcr.io/otfabric/dnp3-interop-dnp3py@sha256:129d3678f18c2f62b410d74c17f41661fe6b3588bfe4950242fb01ac006fe8fd"
)

// adapters returns the reference implementations to test against. The image
// of each can be overridden, for example to try a candidate:
//
//	DNP3_INTEROP_STEPFUNC_IMAGE, DNP3_INTEROP_OPENDNP3_IMAGE,
//	DNP3_INTEROP_DSCSYSTEMS_IMAGE, DNP3_INTEROP_DNP3PY_IMAGE
//
// DNP3_INTEROP_ADAPTERS restricts the run to a comma-separated subset.
// Not every image has both roles: a test asks the image (see
// [adapter.needRole]) and skips what it lacks.
func adapters(t testing.TB) []adapter {
	t.Helper()
	all := []adapter{
		{"stepfunc", getenv("DNP3_INTEROP_STEPFUNC_IMAGE", defaultStepfuncImage)},
		{"opendnp3", getenv("DNP3_INTEROP_OPENDNP3_IMAGE", defaultOpendnp3Image)},
		{"dscsystems", getenv("DNP3_INTEROP_DSCSYSTEMS_IMAGE", defaultDscsystemsImage)},
		{"dnp3py", getenv("DNP3_INTEROP_DNP3PY_IMAGE", defaultDnp3pyImage)},
	}
	only := os.Getenv("DNP3_INTEROP_ADAPTERS")
	if only == "" {
		return all
	}
	var out []adapter
	for _, a := range all {
		for _, want := range strings.Split(only, ",") {
			if strings.TrimSpace(want) == a.name {
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("DNP3_INTEROP_ADAPTERS=%q selects no adapter", only)
	}
	return out
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// capabilities is the document "print-capabilities" prints.
type capabilities struct {
	Adapter string `json:"adapter"`
	Roles   struct {
		Server bool `json:"server"`
		Client bool `json:"client"`
	} `json:"roles"`
	Features map[string]bool `json:"features"`
	// PointTypes are the fixture sections the outstation serves.
	PointTypes []string `json:"pointTypes"`
	// ServerFeatures are the features of the server role where they differ
	// from Features (contract 1.2).
	ServerFeatures map[string]bool `json:"serverFeatures"`
}

var capabilitiesCache sync.Map // image -> *capabilities

func (a adapter) capabilities(t testing.TB) *capabilities {
	t.Helper()
	if c, ok := capabilitiesCache.Load(a.image); ok {
		return c.(*capabilities)
	}
	out, stderr, err := docker("run", "--rm", a.image, "print-capabilities")
	if err != nil {
		t.Fatalf("print-capabilities of %s: %v\n%s", a.image, err, stderr)
	}
	caps := &capabilities{}
	if err := json.Unmarshal([]byte(out), caps); err != nil {
		t.Fatalf("capabilities of %s are not JSON: %v", a.image, err)
	}
	capabilitiesCache.Store(a.image, caps)
	return caps
}

// needRole skips the test when the image lacks the role: "server" (a
// reference outstation) or "client" (a reference master).
func (a adapter) needRole(t testing.TB, role string) {
	t.Helper()
	r := a.capabilities(t).Roles
	if (role == "server" && !r.Server) || (role == "client" && !r.Client) {
		t.Skipf("%s has no %s role", a.name, role)
	}
}

// needFixture skips the test when the image's outstation cannot serve
// every point type of the named fixture.
func (a adapter) needFixture(t testing.TB, name string) {
	t.Helper()
	have := map[string]bool{}
	for _, pt := range a.capabilities(t).PointTypes {
		have[pt] = true
	}
	for _, pt := range a.fixtureNamed(t, name).pointTypes() {
		if !have[pt] {
			t.Skipf("%s's outstation does not serve %s (fixture %s)", a.name, pt, name)
		}
	}
}

// needServer skips the test when the image's outstation lacks a feature:
// serverFeatures where it names it, features otherwise.
func (a adapter) needServer(t testing.TB, features ...string) {
	t.Helper()
	c := a.capabilities(t)
	for _, f := range features {
		v, ok := c.ServerFeatures[f]
		if !ok {
			v = c.Features[f]
		}
		if !v {
			t.Skipf("%s's outstation does not declare %s", a.name, f)
		}
	}
}

// need skips the test when the image does not declare every feature.
func (a adapter) need(t testing.TB, features ...string) {
	t.Helper()
	for _, f := range features {
		if !a.capabilities(t).Features[f] {
			t.Skipf("%s does not declare %s", a.name, f)
		}
	}
}

var fixtureCache sync.Map // image and fixture name -> []byte

// fixture returns the baseline fixture baked into the image.
func (a adapter) fixture(t testing.TB) *fixture {
	t.Helper()
	return a.fixtureNamed(t, "baseline")
}

// fixtureNamed returns the named fixture baked into the image.
func (a adapter) fixtureNamed(t testing.TB, name string) *fixture {
	t.Helper()
	raw, ok := fixtureCache.Load(a.image + " " + name)
	if !ok {
		out, stderr, err := docker("run", "--rm", a.image, "print-fixture", name)
		if err != nil {
			t.Fatalf("print-fixture of %s: %v\n%s", a.image, err, stderr)
		}
		raw = []byte(out)
		fixtureCache.Store(a.image+" "+name, raw)
	}
	f, err := parseFixture(raw.([]byte))
	if err != nil {
		t.Fatalf("fixture of %s: %v", a.image, err)
	}
	return f
}

var containerSeq atomic.Int64

func docker(args ...string) (stdout, stderr string, err error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

// refServer is a running reference outstation container.
type refServer struct {
	adapter adapter
	name    string
	addr    string // host:port on loopback
}

// startServer runs the reference outstation of a with the baseline fixture
// and waits until it is ready.
func startServer(t testing.TB, a adapter, extra ...string) *refServer {
	t.Helper()
	return startServerSpec(t, a, serverSpec{args: extra})
}

// serverSpec says how to run a reference outstation.
type serverSpec struct {
	// args follow the server command.
	args []string
	// docker are extra options of docker run: volumes, a network, a name.
	docker []string
	// port is the container port published on loopback: "20000" when
	// empty, "-" for none (a test on a docker network).
	port string
	// script, when set, runs instead of the server command with /bin/sh;
	// it ends by exec'ing the server (the serial bridge).
	script string
}

// fixtureName is the fixture the server serves: the one of --fixture
// (/fixtures/NAME/fixture.json), the baseline otherwise.
func (spec serverSpec) fixtureName() string {
	for i, a := range spec.args {
		if a == "--fixture" && i+1 < len(spec.args) {
			parts := strings.Split(spec.args[i+1], "/")
			if len(parts) >= 3 {
				return parts[len(parts)-2]
			}
		}
	}
	return "baseline"
}

// startServerSpec runs a reference outstation as spec says and waits until
// it is ready.
func startServerSpec(t testing.TB, a adapter, spec serverSpec) *refServer {
	t.Helper()
	a.needRole(t, "server")
	a.needFixture(t, spec.fixtureName())
	name := fmt.Sprintf("go-dnp3-interop-%s-%d-%d", a.name, os.Getpid(), containerSeq.Add(1))
	args := append([]string{"run", "-d", "--name", name}, spec.docker...)
	s := &refServer{adapter: a, name: name}
	if spec.port != "-" {
		cport := spec.port
		if cport == "" {
			cport = "20000"
		}
		port := freePort(t)
		args = append(args, "-p", fmt.Sprintf("127.0.0.1:%d:%s", port, cport))
		s.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	if spec.script != "" {
		args = append(args, "--entrypoint", "/bin/sh", a.image, "-c", spec.script)
	} else {
		args = append(append(args, a.image, "server"), spec.args...)
	}
	if _, stderr, err := docker(args...); err != nil {
		t.Fatalf("start %s server: %v\n%s", a.name, err, stderr)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, errOut, _ := docker("logs", "--tail", "80", name)
			t.Logf("%s server log:\n%s%s", a.name, out, errOut)
		}
		_, _, _ = docker("rm", "-f", name)
	})
	s.waitReady(t)
	return s
}

// waitReady waits for the readiness file: readiness is the file, never
// the open port or a delay.
func (s *refServer) waitReady(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, _, err := docker("exec", s.name, "test", "-f", "/run/dnp3-interop/ready"); err == nil {
			return
		}
		if state, _, _ := docker("inspect", "--format", "{{.State.Status}}", s.name); strings.TrimSpace(state) != "running" {
			t.Fatalf("%s server is %q, not running", s.adapter.name, strings.TrimSpace(state))
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s server not ready after 60s", s.adapter.name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// event is one line of the server's JSON Lines event stream.
type event map[string]any

func (s *refServer) events(t testing.TB) []event {
	t.Helper()
	out, _, err := docker("logs", s.name)
	if err != nil {
		t.Fatalf("logs of %s server: %v", s.adapter.name, err)
	}
	var evs []event
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("%s server wrote a stdout line that is not JSON: %q", s.adapter.name, line)
		}
		evs = append(evs, e)
	}
	return evs
}

// waitEvent returns the last event that satisfies match, waiting for one.
func (s *refServer) waitEvent(t testing.TB, what string, match func(event) bool) event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := s.events(t)
		for i := len(evs) - 1; i >= 0; i-- {
			if match(evs[i]) {
				return evs[i]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s server reported no %s event; events: %v", s.adapter.name, what, evs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// result is the document a reference client prints.
type result struct {
	OK        bool   `json:"ok"`
	Operation string `json:"operation"`
	Connected bool   `json:"connected"`
	Error     *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	IIN             []string     `json:"iin"`
	Objects         []resultObj  `json:"objects"`
	CommandStatus   *string      `json:"commandStatus"`
	RestartDelayMs  *float64     `json:"restartDelayMs"`
	CommandStatuses []*string    `json:"commandStatuses"`
	Attributes      []resultAttr `json:"attributes"`
	File            *fileEntry   `json:"file"`
	Files           []fileEntry  `json:"files"`
	FileStatus      *string      `json:"fileStatus"`

	exit int
}

type resultObj struct {
	Group       int      `json:"group"`
	Variation   int      `json:"variation"`
	Index       int      `json:"index"`
	Value       any      `json:"value"`
	Flags       []string `json:"flags"`
	Time        string   `json:"time"`
	Unsolicited bool     `json:"unsolicited"`
	// Contract 1.2.
	Status      string   `json:"status"`
	Units       *float64 `json:"units"`
	Association *float64 `json:"association"`
}

// resultAttr is a device attribute of attribute-read (contract 1.3).
type resultAttr struct {
	Set       int    `json:"set"`
	Variation int    `json:"variation"`
	Type      string `json:"type"`
	Value     any    `json:"value"`
}

// fileEntry is a file of a file operation's result.
type fileEntry struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Size        float64 `json:"size"`
	Permissions string  `json:"permissions"`
	Content     string  `json:"content"`
}

func (r *result) errorCode() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

// runClient runs one operation of a's reference master against the
// outstation at port on the host. The container reaches the host as
// host.docker.internal.
func runClient(t testing.TB, a adapter, port int, op string, args ...string) *result {
	t.Helper()
	return runClientSpec(t, a, nil, append([]string{op, "--host", "host.docker.internal", "--port", strconv.Itoa(port)}, args...))
}

// clientArgs are the arguments of every client run: the baseline fixture's
// addresses.
var clientArgs = []string{"--local-addr", "1", "--remote-addr", "1024"}

// withDefaults returns the clientArgs that argv does not set itself.
func withDefaults(argv []string) []string {
	var out []string
	for i := 0; i < len(clientArgs); i += 2 {
		if !slices.Contains(argv, clientArgs[i]) {
			out = append(out, clientArgs[i], clientArgs[i+1])
		}
	}
	return out
}

// runClientSpec runs the reference master with argv after the client
// command (the operation first) and extra docker run options.
func runClientSpec(t testing.TB, a adapter, dockerArgs []string, argv []string) *result {
	t.Helper()
	a.needRole(t, "client")
	cmd := append(append([]string{"run", "--rm", "--add-host=host.docker.internal:host-gateway"}, dockerArgs...), a.image, "client")
	return runClientCmd(t, a, argv[0], append(append(cmd, argv...), withDefaults(argv)...))
}

// runClientScript runs the reference master from a /bin/sh script that
// ends by exec'ing "dnp3-interop client" with argv (the serial bridge).
func runClientScript(t testing.TB, a adapter, script string, argv []string) *result {
	t.Helper()
	a.needRole(t, "client")
	script += "\nexec dnp3-interop client " + shellJoin(append(argv, withDefaults(argv)...))
	return runClientCmd(t, a, argv[0], []string{"run", "--rm", "--add-host=host.docker.internal:host-gateway",
		"--entrypoint", "/bin/sh", a.image, "-c", script})
}

func runClientCmd(t testing.TB, a adapter, op string, cmd []string) *result {
	t.Helper()
	out, stderr, err := docker(cmd...)
	r := &result{}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s client: %v\n%s", a.name, err, stderr)
	}
	line := strings.TrimSpace(out)
	if i := strings.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal([]byte(line), r); err != nil {
		t.Fatalf("%s client %s printed no result document: %v\nstdout: %s\nstderr: %s", a.name, op, err, out, stderr)
	}
	if !r.OK {
		msg := ""
		if r.Error != nil {
			msg = r.Error.Message
		}
		t.Logf("%s client %s: exit=%d error=%s %q; stderr:\n%s", a.name, op, r.exit, r.errorCode(), msg, lastLines(stderr, 15))
	}
	return r
}

// shellJoin quotes args for /bin/sh.
func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

// dockerNetwork creates a network for the duration of the test, for
// containers that must see each other's addresses as they are.
func dockerNetwork(t testing.TB) string {
	t.Helper()
	name := fmt.Sprintf("go-dnp3-interop-%d-%d", os.Getpid(), containerSeq.Add(1))
	if _, stderr, err := docker("network", "create", name); err != nil {
		t.Fatalf("create network: %v\n%s", err, stderr)
	}
	t.Cleanup(func() { _, _, _ = docker("network", "rm", name) })
	return name
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// requireDocker skips the suite when Docker is not available.
func requireDocker(t testing.TB) {
	t.Helper()
	if _, _, err := docker("version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skip("Docker is not available")
	}
}

// knownBugs are deviations of a reference from the fixture behaviour that
// dnp3-interop records in tests/known-bugs.tsv. A test checks the
// behaviour and, for an adapter listed here, logs the deviation instead of
// failing. The key names the behaviour; the value is the record.
var knownBugs = map[string]map[string]string{
	"dscsystems": {
		"freeze-clear-without-frozen": "v0.8.1: FREEZE AND CLEAR leaves a counter that has no frozen counter of the same index uncleared",
	},
}

// knownBug reports whether behaviour is a recorded bug of a, logging it.
func knownBug(t testing.TB, a adapter, behaviour string) bool {
	t.Helper()
	if why, ok := knownBugs[a.name][behaviour]; ok {
		t.Logf("known bug of %s: %s", a.name, why)
		return true
	}
	return false
}
