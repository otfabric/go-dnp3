// SPDX-License-Identifier: MIT

// Command udpmaster is the go-dnp3 master for the interop tests that must
// run inside a container: an outstation whose UDP socket is connected to
// one peer (opendnp3) only hears a master whose address it can name, and
// address translation between the host and the containers hides the
// host's. It runs an integrity poll from a fixed UDP port, retrying until
// the outstation answers, and prints {"ok", "objects", "error"}.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"time"

	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/link"
)

func main() {
	addr := flag.String("addr", "", "the outstation's UDP endpoint")
	local := flag.Int("local-port", 20000, "own UDP port")
	outstation := flag.Uint("outstation", 1024, "the outstation's link address")
	wait := flag.Duration("wait", 30*time.Second, "how long to try")
	flag.Parse()

	out := struct {
		OK      bool   `json:"ok"`
		Objects int    `json:"objects"`
		Error   string `json:"error,omitempty"`
	}{}
	defer func() {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		if !out.OK {
			os.Exit(1)
		}
	}()
	open := func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
		d := net.Dialer{LocalAddr: &net.UDPAddr{Port: *local}}
		conn, err := d.DialContext(ctx, "udp", *addr)
		if err != nil {
			return nil, nil, err
		}
		return conn, conn.RemoteAddr(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()
	c, err := client.Dial(ctx, *addr, client.WithStream(open), client.WithAutoIntegrity(false),
		client.WithAddresses(1, link.Address(*outstation)), client.WithResponseTimeout(2*time.Second))
	if err != nil {
		out.Error = err.Error()
		return
	}
	defer func() { _ = c.Close() }()
	for {
		res, err := c.IntegrityPoll(ctx)
		if err == nil {
			out.OK, out.Objects = true, len(res.Measurements())
			return
		}
		if ctx.Err() != nil {
			out.Error = err.Error()
			return
		}
	}
}
