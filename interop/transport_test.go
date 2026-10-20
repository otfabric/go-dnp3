//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
)

// The transports of contract 1.1, both directions: TLS (mutual), UDP and
// serial lines.

// pki is a test PKI written as PEM files into a directory the containers
// mount at /pki: ca.pem; server.pem/.key for the outstation (localhost,
// host.docker.internal, 127.0.0.1); client.pem/.key for the master; and
// rogue.pem/.key, a master certificate of another CA.
type pki struct {
	dir    string
	pool   *x509.CertPool
	server tls.Certificate
	client tls.Certificate
	rogue  tls.Certificate
}

var (
	pkiOnce sync.Once
	pkiVal  *pki
	pkiErr  error
)

func testPKI(t *testing.T) *pki {
	t.Helper()
	pkiOnce.Do(func() { pkiVal, pkiErr = makePKI() })
	if pkiErr != nil {
		t.Fatalf("test PKI: %v", pkiErr)
	}
	return pkiVal
}

func makePKI() (*pki, error) {
	// Not t.TempDir: the PKI is shared by the tests of the run. The
	// containers run as uid 10001, so the files are world-readable.
	dir, err := os.MkdirTemp("", "go-dnp3-interop-pki-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	p := &pki{dir: dir, pool: x509.NewCertPool()}
	serial := int64(1)
	newCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		serial++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, nil, nil, err
		}
		cert, err := x509.ParseCertificate(der)
		return cert, key, der, err
	}
	leaf := func(file string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage, server bool) (tls.Certificate, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		serial++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: file},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if server {
			tmpl.DNSNames = []string{"localhost", "host.docker.internal"}
			tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return tls.Certificate{}, err
		}
		pk, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return tls.Certificate{}, err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
		if err := writePublic(filepath.Join(dir, file+".pem"), certPEM); err != nil {
			return tls.Certificate{}, err
		}
		if err := writePublic(filepath.Join(dir, file+".key"), keyPEM); err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	ca, caKey, caDER, err := newCA("go-dnp3 interop CA")
	if err != nil {
		return nil, err
	}
	p.pool.AddCert(ca)
	if err := writePublic(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})); err != nil {
		return nil, err
	}
	if p.server, err = leaf("server", ca, caKey, x509.ExtKeyUsageServerAuth, true); err != nil {
		return nil, err
	}
	if p.client, err = leaf("client", ca, caKey, x509.ExtKeyUsageClientAuth, false); err != nil {
		return nil, err
	}
	other, otherKey, _, err := newCA("another CA")
	if err != nil {
		return nil, err
	}
	if p.rogue, err = leaf("rogue", other, otherKey, x509.ExtKeyUsageClientAuth, false); err != nil {
		return nil, err
	}
	return p, nil
}

func writePublic(name string, b []byte) error { return os.WriteFile(name, b, 0o644) }

func (p *pki) mount() []string { return []string{"-v", p.dir + ":/pki:ro"} }

// clientTLS is the master's configuration: our CA, the client
// certificate, the name localhost.
func (p *pki) clientTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{RootCAs: p.pool, Certificates: []tls.Certificate{cert}, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

// serverTLS demands a client certificate of our CA.
func (p *pki) serverTLS() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{p.server}, ClientCAs: p.pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
}

// checkStatic compares the static objects of an integrity poll with the
// fixture.
func checkStatic(t *testing.T, f *fixture, count int) {
	t.Helper()
	if want := len(f.expectedStatic()); count != want {
		t.Errorf("integrity poll returned %d static objects, fixture %d", count, want)
	}
}

func staticCount(res *client.Result) int {
	n := 0
	for _, m := range res.Measurements() {
		if !m.Event {
			n++
		}
	}
	return n
}

func TestClientTLS(t *testing.T) {
	requireDocker(t)
	p := testPKI(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "tls")
			s := startServerSpec(t, a, serverSpec{docker: p.mount(),
				args: []string{"--tls-cert", "/pki/server.pem", "--tls-key", "/pki/server.key", "--tls-ca", "/pki/ca.pem"}})
			c := dialRef(t, s, client.WithTLS(p.clientTLS(p.client)))
			res, err := c.IntegrityPoll(tctx(t))
			if err != nil {
				t.Fatal(err)
			}
			checkStatic(t, a.fixture(t), staticCount(res))

			// A master certificate of another CA is refused: at the
			// handshake, or with TLS 1.3 at the first request.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rc, err := client.Dial(ctx, s.addr, client.WithTLS(p.clientTLS(p.rogue)), client.WithAutoIntegrity(false),
				client.WithAddresses(1, link.Address(a.fixture(t).Outstation.Address)), client.WithResponseTimeout(2*time.Second))
			if err == nil {
				_, err = rc.IntegrityPoll(ctx)
				_ = rc.Close()
			}
			if err == nil {
				t.Fatal("the outstation accepted a master certificate of another CA")
			}
		})
	}
}

func TestServerTLS(t *testing.T) {
	requireDocker(t)
	p := testPKI(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "tls")
			st, err := newStation(a.fixture(t))
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = st.srv.Serve(tls.NewListener(l, p.serverTLS())) }()
			t.Cleanup(func() { _ = st.srv.Close() })
			port := l.Addr().(*net.TCPAddr).Port

			tlsArgs := func(cert string) []string {
				return []string{"integrity-poll", "--host", "host.docker.internal", "--port", strconv.Itoa(port),
					"--tls", "--tls-ca", "/pki/ca.pem", "--tls-cert", "/pki/" + cert + ".pem", "--tls-key", "/pki/" + cert + ".key"}
			}
			r := runClientSpec(t, a, p.mount(), tlsArgs("client"))
			if !r.OK {
				t.Fatalf("integrity poll over TLS failed: %s", r.errorCode())
			}
			if want := len(a.fixture(t).expectedStatic()); len(r.Objects) != want {
				t.Errorf("%d objects over TLS, fixture %d", len(r.Objects), want)
			}
			if r := runClientSpec(t, a, p.mount(), tlsArgs("rogue")); r.OK {
				t.Fatal("go-dnp3 accepted a master certificate of another CA")
			}
		})
	}
}

func TestClientUDP(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "udp")
			if a.name == "opendnp3" {
				// Its socket is connected to the --udp-peer endpoint: the
				// master must run where its address is what the
				// outstation sees.
				clientUDPInNetwork(t, a)
				return
			}
			s := startServerSpec(t, a, serverSpec{port: "20000/udp", args: []string{"--transport", "udp"}})
			c := dialRef(t, s, client.WithStream(client.UDP(s.addr)))
			res, err := c.IntegrityPoll(tctx(t))
			if err != nil {
				t.Fatal(err)
			}
			checkStatic(t, a.fixture(t), staticCount(res))
		})
	}
}

// clientUDPInNetwork runs the go-dnp3 master (testdata/udpmaster, built
// for the Docker host) in a container on one network with the outstation.
func clientUDPInNetwork(t *testing.T, a adapter) {
	t.Helper()
	bin := udpMasterBinary(t)
	nw := dockerNetwork(t)
	master := fmt.Sprintf("go-dnp3-interop-master-%d-%d", os.Getpid(), containerSeq.Add(1))
	// The master container first, idle, so that its address is known
	// when the outstation starts.
	if _, stderr, err := docker("run", "-d", "--name", master, "--network", nw, "-v", filepath.Dir(bin)+":/m:ro",
		"--entrypoint", "/bin/sh", a.image, "-c", "while [ ! -e /tmp/go ]; do sleep 0.05; done; exec /m/udpmaster -addr \"$(cat /tmp/go)\""); err != nil {
		t.Fatalf("start the master container: %v\n%s", err, stderr)
	}
	t.Cleanup(func() { _, _, _ = docker("rm", "-f", master) })
	ip, _, err := docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", master)
	if err != nil {
		t.Fatal(err)
	}
	s := startServerSpec(t, a, serverSpec{port: "-", docker: []string{"--network", nw},
		args: []string{"--transport", "udp", "--udp-peer", strings.TrimSpace(ip) + ":20000"}})
	oip, _, err := docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", s.name)
	if err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := docker("exec", master, "sh", "-c", "echo "+strings.TrimSpace(oip)+":20000 > /tmp/go"); err != nil {
		t.Fatalf("start the master: %v\n%s", err, stderr)
	}
	if _, stderr, err := docker("wait", master); err != nil {
		t.Fatalf("wait for the master: %v\n%s", err, stderr)
	}
	out, stderr, _ := docker("logs", master)
	var r struct {
		OK      bool   `json:"ok"`
		Objects int    `json:"objects"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(lastLines(out, 1)), &r); err != nil {
		t.Fatalf("the master printed no result: %v\n%s%s", err, out, stderr)
	}
	if !r.OK {
		t.Fatalf("integrity poll over UDP from the network: %s\n%s", r.Error, lastLines(stderr, 15))
	}
	checkStatic(t, a.fixture(t), r.Objects)
}

var (
	udpMasterOnce sync.Once
	udpMasterBin  string
	udpMasterErr  error
)

// udpMasterBinary builds testdata/udpmaster for the Docker host's
// architecture, once per run.
func udpMasterBinary(t *testing.T) string {
	t.Helper()
	udpMasterOnce.Do(func() {
		arch, _, err := docker("info", "--format", "{{.Architecture}}")
		if err != nil {
			udpMasterErr = err
			return
		}
		goarch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[strings.TrimSpace(arch)]
		if goarch == "" {
			goarch = runtime.GOARCH
		}
		dir, err := os.MkdirTemp("", "go-dnp3-interop-bin-")
		if err != nil {
			udpMasterErr = err
			return
		}
		_ = os.Chmod(dir, 0o755)
		udpMasterBin = filepath.Join(dir, "udpmaster")
		cmd := exec.Command("go", "build", "-o", udpMasterBin, "./testdata/udpmaster")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
		if out, err := cmd.CombinedOutput(); err != nil {
			udpMasterErr = fmt.Errorf("%v\n%s", err, out)
		}
	})
	if udpMasterErr != nil {
		t.Fatalf("build the in-container master: %v", udpMasterErr)
	}
	return udpMasterBin
}

func TestServerUDP(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "udp")
			st, err := newStation(a.fixture(t))
			if err != nil {
				t.Fatal(err)
			}
			pc, err := net.ListenPacket("udp", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = st.srv.ServeUDP(pc) }()
			t.Cleanup(func() { _ = st.srv.Close() })
			r := runClient(t, a, pc.LocalAddr().(*net.UDPAddr).Port, "integrity-poll", "--transport", "udp")
			if !r.OK {
				t.Fatalf("integrity poll over UDP failed: %s", r.errorCode())
			}
			if want := len(a.fixture(t).expectedStatic()); len(r.Objects) != want {
				t.Errorf("%d objects over UDP, fixture %d", len(r.Objects), want)
			}
		})
	}
}

// serialBridge is the outstation side of a serial line in a container,
// bridged to TCP port 20001 (CONTAINER_CONTRACT.md, Serial).
const serialBridge = `socat pty,link=/tmp/ttyDNP3,raw,echo=0 pty,link=/tmp/ttyLINE,raw,echo=0 &
while [ ! -e /tmp/ttyDNP3 ] || [ ! -e /tmp/ttyLINE ]; do sleep 0.05; done
socat -t 0.05 tcp-listen:20001,reuseaddr,fork file:/tmp/ttyLINE,raw,echo=0 &
exec dnp3-interop server --transport serial --serial-device /tmp/ttyDNP3`

func TestClientSerial(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "serial")
			s := startServerSpec(t, a, serverSpec{port: "20001", script: serialBridge})
			// The bridge carries the octets of the line: the master
			// speaks the serial link layer over the TCP connection.
			c := dialRef(t, s)
			res, err := c.IntegrityPoll(tctx(t))
			if err != nil {
				t.Fatal(err)
			}
			checkStatic(t, a.fixture(t), staticCount(res))
		})
	}
}

func TestServerSerial(t *testing.T) {
	requireDocker(t)
	for _, a := range adapters(t) {
		t.Run(a.name, func(t *testing.T) {
			a.need(t, "serial")
			_, port := serveFixture(t, a)
			// The master's end of the line is a pseudo-terminal bridged
			// to go-dnp3's outstation on the host.
			bridge := fmt.Sprintf(`socat pty,link=/tmp/ttyDNP3,raw,echo=0 tcp:host.docker.internal:%d &
while [ ! -e /tmp/ttyDNP3 ]; do sleep 0.05; done`, port)
			r := runClientScript(t, a, bridge, []string{"integrity-poll", "--transport", "serial", "--serial-device", "/tmp/ttyDNP3"})
			if !r.OK {
				t.Fatalf("integrity poll over the serial line failed: %s", r.errorCode())
			}
			if want := len(a.fixture(t).expectedStatic()); len(r.Objects) != want {
				t.Errorf("%d objects over the serial line, fixture %d", len(r.Objects), want)
			}
		})
	}
}
