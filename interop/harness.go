//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
// the dnp3-interop container contract 1.5.
type adapter struct {
	name  string
	image string
}

// The reference images this version of go-dnp3 is qualified against:
// otfabric/dnp3-interop v0.12.1 (opendnp3 3.1.2, DSC go-dnp3 v0.8.2,
// dnp3py 0.6.0, cB-Sigma dnp3 v0.3.1, nfm-dnp3 1.0.1). The images are pinned by multi-arch index digest so that
// a run is reproducible. Moving to another release of dnp3-interop means changing these
// constants; the Makefile and the interop workflow follow.
const (
	interopRelease         = "v0.12.1"
	defaultOpendnp3Image   = "ghcr.io/otfabric/dnp3-interop-opendnp3@sha256:22d5d0c03d7648af2b059898fb49d2e5dcd5a3e8a722935a5adfd6912bb21655"
	defaultDscsystemsImage = "ghcr.io/otfabric/dnp3-interop-dscsystems@sha256:0e524995121752018db491c49bf08a5fde2098a2ce51541cdf1dff0a9b18f1bd"
	defaultDnp3pyImage     = "ghcr.io/otfabric/dnp3-interop-dnp3py@sha256:6be83712526017b0247a90cfd1a36fd679b87abb01b54ff438a52332aaa26469"
	defaultCbsigmaImage    = "ghcr.io/otfabric/dnp3-interop-cbsigma@sha256:5469a14546b5bc3a5c75fdbffe4b4d8f9dd7113357cfb74daaba8db0c1d998ed"
	defaultNfmdnp3Image    = "ghcr.io/otfabric/dnp3-interop-nfmdnp3@sha256:6e7f72f58cc9a59804c6e6fa3ff368593e40bf03596934d642724c96191a2ff2"
)

// adapters returns the reference implementations to test against. The image
// of each can be overridden, for example to try a candidate:
//
//	DNP3_INTEROP_OPENDNP3_IMAGE, DNP3_INTEROP_DSCSYSTEMS_IMAGE,
//	DNP3_INTEROP_DNP3PY_IMAGE, DNP3_INTEROP_CBSIGMA_IMAGE,
//	DNP3_INTEROP_NFMDNP3_IMAGE
//
// DNP3_INTEROP_ADAPTERS restricts the run to a comma-separated subset.
//
// otfabric is go-dnp3 itself, as published by otfabric/dnp3-interop. It is
// not a reference: it runs only when DNP3_INTEROP_OTFABRIC_IMAGE names an
// image, and what it shows is compatibility between releases of this library,
// not independent verification.
//
// Not every image has both roles: a test asks the image (see
// [adapter.needRole]) and skips what it lacks.
func adapters(t testing.TB) []adapter {
	t.Helper()
	all := []adapter{
		{"opendnp3", getenv("DNP3_INTEROP_OPENDNP3_IMAGE", defaultOpendnp3Image)},
		{"dscsystems", getenv("DNP3_INTEROP_DSCSYSTEMS_IMAGE", defaultDscsystemsImage)},
		{"dnp3py", getenv("DNP3_INTEROP_DNP3PY_IMAGE", defaultDnp3pyImage)},
		{"cbsigma", getenv("DNP3_INTEROP_CBSIGMA_IMAGE", defaultCbsigmaImage)},
		{"nfmdnp3", getenv("DNP3_INTEROP_NFMDNP3_IMAGE", defaultNfmdnp3Image)},
		{"otfabric", os.Getenv("DNP3_INTEROP_OTFABRIC_IMAGE")},
	}
	only := os.Getenv("DNP3_INTEROP_ADAPTERS")
	var out []adapter
	for _, a := range all {
		selected := only == ""
		for want := range strings.SplitSeq(only, ",") {
			selected = selected || strings.TrimSpace(want) == a.name
		}
		switch {
		case !selected:
		case a.image != "":
			out = append(out, a)
		case only != "":
			t.Fatalf("DNP3_INTEROP_ADAPTERS selects %s, which has no image: set DNP3_INTEROP_%s_IMAGE",
				a.name, strings.ToUpper(a.name))
		}
	}
	if only == "" {
		return out
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
	// FrozenEventPolicies are what the outstation can do for a freeze that
	// leaves a frozen value as it was, its default first (contract 1.4).
	FrozenEventPolicies []string `json:"frozenEventPolicies"`
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
	f := a.fixtureNamed(t, "baseline")
	if withoutUnsolicited[a.name] {
		f.Outstation.Unsolicited = false
	}
	return f
}

// withoutUnsolicited are the images whose master go-dnp3's outstation
// serves the baseline without unsolicited responses.
var withoutUnsolicited = map[string]bool{
	// nfm-dnp3 1.0.1 has no outstation, and its master sends the
	// application confirm as CONFIRMED_USER_DATA, so it cannot confirm the
	// null unsolicited response of the baseline (dnp3-interop known bug
	// nfmdnp3-confirm-link-service).
	"nfmdnp3": true,
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

// docker runs the docker CLI with args, without a shell.
func docker(args ...string) (stdout, stderr string, err error) {
	return dockerIn(nil, args...)
}

// dockerIn is docker with stdin.
func dockerIn(stdin io.Reader, args ...string) (stdout, stderr string, err error) {
	var out, errb bytes.Buffer
	// The program is the constant "docker"; the arguments are the harness's
	// own and reach it as argv, never through a shell.
	cmd := exec.Command("docker")
	cmd.Args = append(cmd.Args, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &out, &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

// volumeFile is one file of a dockerVolume.
type volumeFile struct {
	name string
	mode int64
	data []byte
}

// dockerVolume creates a volume for the duration of the test that holds
// files, owned by root with their mode, and returns its name. The files
// never touch the host's file system: the containers run as another user
// than the test, and a bind mount would need them world-readable there. The
// volume is filled through a created, never started, container of image.
func dockerVolume(t testing.TB, image string, files []volumeFile) string {
	t.Helper()
	name := fmt.Sprintf("go-dnp3-interop-%d-%d", os.Getpid(), containerSeq.Add(1))
	if _, stderr, err := docker("volume", "create", name); err != nil {
		t.Fatalf("create volume: %v\n%s", err, stderr)
	}
	t.Cleanup(func() { _, _, _ = docker("volume", "rm", "-f", name) })
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg, ModTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := docker("container", "create", "--name", name, "-v", name+":/v", "--entrypoint", "/bin/true", image); err != nil {
		t.Fatalf("create the volume's container: %v\n%s", err, stderr)
	}
	defer func() { _, _, _ = docker("rm", "-f", name) }()
	if _, stderr, err := dockerIn(&buf, "cp", "-", name+":/v"); err != nil {
		t.Fatalf("fill volume: %v\n%s", err, stderr)
	}
	return name
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
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
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
		for _, ev := range slices.Backward(evs) {
			if match(ev) {
				return ev
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
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
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

// hostIP is the address of this host that the containers reach as
// host.docker.internal (--add-host=host.docker.internal:host-gateway).
// Docker Desktop forwards host-gateway to the host's loopback, so the
// listeners bind 127.0.0.1. Docker Engine on Linux maps host-gateway to the
// gateway of the default bridge network, so they bind that address. Either
// way nothing listens on all interfaces.
func hostIP(t testing.TB) string {
	t.Helper()
	hostIPOnce.Do(func() { hostIPVal, hostIPErr = findHostIP() })
	if hostIPErr != nil {
		t.Fatalf("the host address the containers reach: %v", hostIPErr)
	}
	return hostIPVal
}

var (
	hostIPOnce sync.Once
	hostIPVal  string
	hostIPErr  error
)

func findHostIP() (string, error) {
	osName, stderr, err := docker("info", "--format", "{{.OperatingSystem}}")
	if err != nil {
		return "", fmt.Errorf("docker info: %v\n%s", err, stderr)
	}
	if strings.Contains(osName, "Docker Desktop") {
		return "127.0.0.1", nil
	}
	out, stderr, err := docker("network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}")
	if err != nil {
		return "", fmt.Errorf("inspect the bridge network: %v\n%s", err, stderr)
	}
	for f := range strings.FieldsSeq(out) {
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("the bridge network has no IPv4 gateway: %q", strings.TrimSpace(out))
}

// hostListenAddr is the address, with port 0, of a listener that the
// containers reach as host.docker.internal.
func hostListenAddr(t testing.TB) string {
	t.Helper()
	return net.JoinHostPort(hostIP(t), "0")
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
		// The job that provisions Docker sets it, so that it cannot pass
		// without having run the suite.
		if os.Getenv("DNP3_REQUIRE_INTEROP") == "1" {
			t.Fatalf("DNP3_REQUIRE_INTEROP=1 and Docker is not available: %v", err)
		}
		t.Skipf("Docker is not available (set DNP3_REQUIRE_INTEROP=1 to fail instead): %v", err)
	}
}

// knownBugs are deviations of a reference from the fixture behaviour that
// dnp3-interop records in tests/known-bugs.tsv. A test checks the
// behaviour and, for an adapter listed here, logs the deviation instead of
// failing. The key names the behaviour; the value is the record.
var knownBugs = map[string]map[string]string{
	"dscsystems": {
		"freeze-clear-without-frozen": "v0.8.2: FREEZE AND CLEAR leaves a counter that has no frozen counter of the same index uncleared",
		"file-info-base-name":         "v0.8.2: GET_FILE_INFO is answered with the last path element, not the requested name of IEEE 1815-2012 4.4.18 (outstation/file.go, onGetFileInfo)",
	},
	"cbsigma": {
		"file-info-base-name": "v0.3.1: GET_FILE_INFO is answered with the last path element, not the requested name of IEEE 1815-2012 4.4.18 (outfile.go, fileInfo)",
	},
	// nfm-dnp3's defects are reported upstream (fxodell/dnp3py#5, #7, #10)
	// and fail its master against every outstation in dnp3-interop.
	"nfmdnp3": {
		"static-objects":  "1.0.1: no decoder for g3v2 and g110, so an integrity poll or all-objects read loses them (fxodell/dnp3py#10)",
		"controls":        "1.0.1: the CROB trip and close codes are swapped and qualifier 0x28 is written with a 1-octet count (fxodell/dnp3py#7, #5)",
		"prefixed-events": "1.0.1: qualifier 0x28 is read with a 1-octet count, so the objects after the first prefixed event header are lost (fxodell/dnp3py#5)",
	},
}

// skipKnownBug skips the test when behaviour is a recorded bug of a, so the
// run reports it with the record instead of failing.
func skipKnownBug(t testing.TB, a adapter, behaviour string) {
	t.Helper()
	if why, ok := knownBugs[a.name][behaviour]; ok {
		t.Skipf("known bug of %s: %s", a.name, why)
	}
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

// len32 is the length n as a uint32 field, at most math.MaxUint32.
func len32(n int) uint32 { return uint32(min(uint64(max(n, 0)), math.MaxUint32)) }
