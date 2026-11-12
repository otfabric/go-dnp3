// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-dnp3/client"
	"github.com/otfabric/go-dnp3/internal/chaosrand"
	"github.com/otfabric/go-dnp3/server"
)

// TestFileOverLargeFragments: with fragments of 100000 octets in both
// directions, the block size of a file transfer is capped at the 65535 of
// its two-octet field, and a file of several blocks is read and written
// back intact whether the master leaves the block size to the outstation
// or asks for the largest.
func TestFileOverLargeFragments(t *testing.T) {
	fs := newMemFS()
	data := make([]byte, 300_000)
	r := chaosrand.New(1)
	for i := range data {
		data[i] = byte(r.Uint32() >> 24)
	}
	fs.files["/big.bin"] = data
	p := newPair(t, nil, []server.Option{server.WithMaxFragment(100_000, 100_000), server.WithFileServer(fs)},
		client.WithMaxFragment(100_000))

	for _, block := range []uint16{0, 0xFFFF} {
		var got bytes.Buffer
		n, err := p.c.ReadFile(ctx(t), "/big.bin", &got, client.FileOptions{MaxBlockSize: block})
		if err != nil || n != int64(len(data)) || !bytes.Equal(got.Bytes(), data) {
			t.Fatalf("read with block size %d: %d octets, %v", block, n, err)
		}
		name := "/copy.bin"
		if _, err := p.c.WriteFile(ctx(t), name, bytes.NewReader(data), len32(len(data)), client.FileOptions{MaxBlockSize: block}); err != nil {
			t.Fatalf("write with block size %d: %v", block, err)
		}
		fs.mu.Lock()
		back := fs.files[name]
		fs.mu.Unlock()
		if !bytes.Equal(back, data) {
			t.Fatalf("written file of %d octets differs", len(back))
		}
	}
}
