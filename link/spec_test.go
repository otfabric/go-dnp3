// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/bits"
	"testing"
	"testing/iotest"
)

// Spec tests: IEEE 1815-2012 clause 9.2.4 (frame format), 9.2.5
// (addresses), 9.2.9 (frame error detection), Tables 9-1 and 9-2, and
// Annex E (CRC), as far as the frame codec answers them on its own. Page
// numbers are printed pages.

// annexETableSHA256 is the SHA-256 of the 256 entries of the Annex E
// lookup table (pp. 774-775), each as two octets, high octet first. The
// digest stands in for the table, which is not reproduced here.
const annexETableSHA256 = "04b02d50f7227f4b24aee7a6ec94ce51b56261f7ee9ee9e49dcf56a2a7529667"

// TestSpecAnnexE_LookupTable checks the CRC against Annex E (pp. 773-775):
// entry i of the lookup table is the accumulator after one octet i, before
// the final inversion of clause 9.2.4.3. The whole table is compared through
// its digest, and four entries are checked directly.
func TestSpecAnnexE_LookupTable(t *testing.T) {
	var table [256]uint16
	var b []byte
	for i := range table {
		table[i] = ^CRC([]byte{byte(i)})
		b = binary.BigEndian.AppendUint16(b, table[i])
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != annexETableSHA256 {
		t.Fatalf("CRC table differs from Annex E: digest %x", sum)
	}
	for i, want := range map[int]uint16{0x00: 0x0000, 0x01: 0x365E, 0x80: 0xA6BC, 0xFF: 0x1235} {
		if table[i] != want {
			t.Errorf("entry %#02x = %#04x, want %#04x", i, table[i], want)
		}
	}
	if table != crcTable {
		t.Fatal("the package table is not the one CRC uses")
	}
}

// TestSpecAnnexE_BitShiftMethod checks CRC against the bit-shifting method
// of Annex E (p. 775) and the polynomial of clause 9.2.4.3 (p. 281):
// x^16+x^13+x^12+x^11+x^10+x^8+x^6+x^5+x^2+1, processed least significant
// bit first (the reversed polynomial), initial value 0, inverted.
func TestSpecAnnexE_BitShiftMethod(t *testing.T) {
	const poly = 1<<13 | 1<<12 | 1<<11 | 1<<10 | 1<<8 | 1<<6 | 1<<5 | 1<<2 | 1
	if bits.Reverse16(poly) != crcPolyReflected {
		t.Fatalf("reversed polynomial %#04x, want %#04x", bits.Reverse16(poly), crcPolyReflected)
	}
	bitwise := func(b []byte) uint16 {
		var crc uint16
		for _, octet := range b {
			for range 8 {
				if (crc^uint16(octet))&1 != 0 {
					crc = crc>>1 ^ bits.Reverse16(poly)
				} else {
					crc >>= 1
				}
				octet >>= 1
			}
		}
		return ^crc
	}
	block := make([]byte, BlockSize)
	for n := 0; n <= BlockSize; n++ {
		for seed := range 32 {
			for i := range block[:n] {
				block[i] = byte(seed*97 + i*31 + n)
			}
			if got, want := CRC(block[:n]), bitwise(block[:n]); got != want {
				t.Fatalf("n=%d seed=%d: CRC %#04x, bit-shift method %#04x", n, seed, got, want)
			}
		}
	}
}

// TestSpecEX9_1 checks example EX 9-1 (clause 9.2.4.3, p. 281): a
// TEST_LINK_STATES frame from 65 519 to 1, control octet 0xF2, has the
// header CRC BF B5, low octet first (Figure 9-7).
func TestSpecEX9_1(t *testing.T) {
	want := unhex(t, "05 64 05 F2 01 00 EF FF BF B5")
	if c := CRC(want[:8]); c != 0xB5BF {
		t.Fatalf("CRC of the EX 9-1 header = %#04x, want 0xb5bf", c)
	}
	f := Frame{Dir: true, Function: PrimaryTestLinkStates, FCB: true, FCV: true, Dest: 1, Src: 65519}
	got, err := f.Encode()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encode = % X (%v), want % X", got, err, want)
	}
	d, n, err := Decode(want)
	if err != nil || n != len(want) || d.Dest != 1 || d.Src != 65519 || d.Function != PrimaryTestLinkStates || !d.Dir || !d.FCB || !d.FCV {
		t.Fatalf("decode: %s, n=%d, %v", d.String(), n, err)
	}
}

// TestSpec9_2_4_1_1_StartOctets checks clause 9.2.4.1.1 (p. 277) with
// 9.2.9 (p. 285): a frame starts with 0x05 0x64; with any other start it is
// discarded.
func TestSpec9_2_4_1_1_StartOctets(t *testing.T) {
	b := stream(t, Frame{Function: PrimaryRequestLinkStatus, Dest: 1, Src: 2})
	if b[0] != 0x05 || b[1] != 0x64 {
		t.Fatalf("start octets % x", b[:2])
	}
	for _, start := range [][2]byte{{0x64, 0x05}, {0x05, 0x65}, {0x00, 0x64}} {
		bad := bytes.Clone(b)
		bad[0], bad[1] = start[0], start[1]
		if _, _, err := Decode(bad); !errors.Is(err, ErrInvalidStart) {
			t.Errorf("start % x: %v", start, err)
		}
	}
}

// TestSpec9_2_4_1_2_LengthField checks clause 9.2.4.1.2 (p. 277): the
// length octet counts the control, destination and source octets and the
// user data, not the CRC octets: 5 for a header alone, at most 255.
func TestSpec9_2_4_1_2_LengthField(t *testing.T) {
	b := stream(t, Frame{Function: PrimaryResetLinkStates})
	if b[2] != 5 || len(b) != HeaderLength {
		t.Fatalf("header alone: length octet %d, %d octets", b[2], len(b))
	}
	for _, n := range []int{1, 15, 16, 17, 32, 249, MaxUserData} {
		b := stream(t, Frame{Function: PrimaryUnconfirmedUserData, Data: make([]byte, n)})
		if int(b[2]) != 5+n {
			t.Errorf("%d octets of user data: length octet %d, want %d", n, b[2], 5+n)
		}
	}
	if b := stream(t, Frame{Function: PrimaryUnconfirmedUserData, Data: make([]byte, MaxUserData)}); b[2] != 255 {
		t.Fatalf("largest frame: length octet %d", b[2])
	}
	// A length octet below 5 is not a frame (9.2.9: the frame length must
	// match the length field).
	for l := range byte(5) {
		h := []byte{Start0, Start1, l, 0xC0, 1, 0, 2, 0}
		h = appendCRC(h, h)
		if _, _, err := Decode(h); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("length octet %d: %v", l, err)
		}
	}
}

// TestSpec9_2_4_1_3_ControlOctet checks the control octet layout of clause
// 9.2.4.1.3 (Figure 9-4, p. 277): DIR bit 7, PRM bit 6, FCB bit 5 and FCV
// bit 4 in primary frames, DFC bit 4 in secondary frames, the function
// code in bits 3..0. Every control octet with a defined function code
// decodes and encodes back to itself, but for bit 5 of a secondary frame.
func TestSpec9_2_4_1_3_ControlOctet(t *testing.T) {
	for c := range 256 {
		fn := Function(c & 0x4F)
		if !fn.Defined() {
			continue
		}
		f := Frame{Dest: 1, Src: 2}
		if fn.HasData() {
			f.Data = []byte{0}
		}
		f.setControl(byte(c))
		if f.Dir != (c&0x80 != 0) || f.Function.Primary() != (c&0x40 != 0) || f.Function.Code() != uint8(c&0x0F) {
			t.Fatalf("control %#02x: %s", c, f.String())
		}
		b, err := f.Encode()
		if err != nil {
			t.Fatalf("control %#02x: %v", c, err)
		}
		want := byte(c)
		if !fn.Primary() {
			want &^= 0x20
		} else if f.FCB != (c&0x20 != 0) || f.FCV != (c&0x10 != 0) {
			t.Fatalf("control %#02x: FCB %v FCV %v", c, f.FCB, f.FCV)
		}
		if b[3] != want {
			t.Fatalf("control %#02x encodes as %#02x", c, b[3])
		}
	}
}

// TestSpec9_2_4_1_3_2_SecondaryBit5 checks clause 9.2.4.1.3.2 (p. 277): in
// a secondary frame (PRM = 0) bit 5 shall always be 0, and bit 4 is DFC
// (9.2.4.1.3.5, p. 278). FCB and FCV are primary fields only.
func TestSpec9_2_4_1_3_2_SecondaryBit5(t *testing.T) {
	for _, fn := range []Function{SecondaryAck, SecondaryNack, SecondaryLinkStatus, SecondaryNotSupported} {
		f := Frame{Function: fn, FCB: true, FCV: true}
		if c := f.Control(); c != byte(fn) {
			t.Errorf("%s with FCB and FCV set on the struct: control %#02x, want %#02x", fn, c, byte(fn))
		}
		f.DFC = true
		if c := f.Control(); c != byte(fn)|0x10 {
			t.Errorf("%s with DFC: control %#02x, want %#02x", fn, c, byte(fn)|0x10)
		}
		f.Dir = true
		if c := f.Control(); c != 0x80|byte(fn)|0x10 {
			t.Errorf("%s from a master with DFC: control %#02x", fn, c)
		}
	}
	// DFC is not a primary field: bit 4 of a primary frame is FCV.
	if c := (&Frame{Function: PrimaryUnconfirmedUserData, DFC: true}).Control(); c != 0x44 {
		t.Fatalf("primary frame with DFC on the struct: control %#02x", c)
	}
}

// TestSpec9_2_4_1_4_AddressOctetOrder checks clauses 9.2.4.1.4 and
// 9.2.4.1.5 (Figures 9-5 and 9-6, p. 280): destination and source are sent
// low octet first.
func TestSpec9_2_4_1_4_AddressOctetOrder(t *testing.T) {
	b := stream(t, Frame{Function: PrimaryRequestLinkStatus, Dest: 0x1234, Src: 0xABCD})
	if !bytes.Equal(b[4:8], []byte{0x34, 0x12, 0xCD, 0xAB}) {
		t.Fatalf("address octets % x", b[4:8])
	}
}

// TestSpec9_2_4_2_UserDataBlocks checks clauses 9.2.4.2 and 9.2.4.3 (p.
// 280-281, Figures 9-3 and 9-7): user data travels in blocks of exactly
// 16 octets but the last, which holds the remainder; each block, and the
// header block over start to source, is followed by its CRC, low octet
// first.
func TestSpec9_2_4_2_UserDataBlocks(t *testing.T) {
	for n := 1; n <= MaxUserData; n++ {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*13 + n)
		}
		b := stream(t, Frame{Function: PrimaryUnconfirmedUserData, Dest: 1, Src: 2, Data: data})
		if c := CRC(b[:8]); b[8] != byte(c) || b[9] != byte(c>>8) {
			t.Fatalf("n=%d: header CRC octets % x, want %#04x low octet first", n, b[8:10], c)
		}
		p, got := b[HeaderLength:], []byte(nil)
		for blocks := 0; len(p) > 0; blocks++ {
			size := min(BlockSize, n-len(got))
			if size != BlockSize && len(got)+size != n {
				t.Fatalf("n=%d: block %d holds %d octets", n, blocks, size)
			}
			c := CRC(p[:size])
			if p[size] != byte(c) || p[size+1] != byte(c>>8) {
				t.Fatalf("n=%d: block %d CRC % x", n, blocks, p[size:size+2])
			}
			got = append(got, p[:size]...)
			p = p[size+2:]
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("n=%d: user data not kept in order", n)
		}
	}
	if _, err := (&Frame{Function: PrimaryUnconfirmedUserData, Data: make([]byte, MaxUserData+1)}).Encode(); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("251 octets of user data: %v", err)
	}
}

// TestSpec9_2_4_4_NoInterFrameGap checks clause 9.2.4.4 (p. 281): frames
// sent back to back, without a gap, are each found, however the octets
// arrive.
func TestSpec9_2_4_4_NoInterFrameGap(t *testing.T) {
	frames := []Frame{
		{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 1, Src: 2, Data: make([]byte, MaxUserData)},
		{Function: SecondaryLinkStatus, Dest: 2, Src: 1},
		{Dir: true, Function: PrimaryConfirmedUserData, FCV: true, Dest: 1, Src: 2, Data: []byte{7}},
		{Dir: true, Function: PrimaryRequestLinkStatus, Dest: 1, Src: 2},
	}
	in := stream(t, frames...)
	for name, src := range map[string]io.Reader{
		"whole":   bytes.NewReader(in),
		"onebyte": iotest.OneByteReader(bytes.NewReader(in)),
		"half":    iotest.HalfReader(bytes.NewReader(in)),
	} {
		r := NewReader(src)
		for i, want := range frames {
			f, err := r.ReadFrame()
			if err != nil || f.Function != want.Function || len(f.Data) != len(want.Data) {
				t.Fatalf("%s: frame %d: %s, %v", name, i, f.String(), err)
			}
		}
		if _, err := r.ReadFrame(); err != io.EOF {
			t.Fatalf("%s: after the last frame: %v", name, err)
		}
	}
}

// TestSpec9_2_5_2_SpecialAddresses checks clause 9.2.5.2 (Table 9-3, p.
// 282): 0xFFFD..0xFFFF are the broadcast addresses, 0xFFFC the self
// address, 0xFFF0..0xFFFB reserved, and station addresses end at 0xFFEF
// (9.2.5.1, p. 281).
func TestSpec9_2_5_2_SpecialAddresses(t *testing.T) {
	for a := Address(0xFFE0); ; a++ {
		broadcast := a >= 0xFFFD
		reserved := a >= 0xFFF0 && a <= 0xFFFB
		if a.Broadcast() != broadcast || a.Reserved() != reserved {
			t.Errorf("%#04x: broadcast %v reserved %v", uint16(a), a.Broadcast(), a.Reserved())
		}
		if a == 0xFFFF {
			break
		}
	}
	if MaxStationAddress != 0xFFEF || SelfAddress != 0xFFFC || SelfAddress.Broadcast() || SelfAddress.Reserved() {
		t.Fatal("station and self addresses")
	}
}

// TestSpecTable9_1And9_2_FunctionCodes checks Tables 9-1 and 9-2 (p. 279):
// the primary codes 0, 2, 3, 4 and 9 and the secondary codes 0, 1, 11 and
// 15 are defined, every other code is not; FCV is 1 for TEST_LINK_STATES
// and CONFIRMED_USER_DATA only; only the two user data functions carry
// data. A frame with an undefined function code is discarded (9.2.9).
func TestSpecTable9_1And9_2_FunctionCodes(t *testing.T) {
	primary := map[uint8]bool{0: true, 2: true, 3: true, 4: true, 9: true}
	secondary := map[uint8]bool{0: true, 1: true, 11: true, 15: true}
	for code := range uint8(16) {
		p, s := Function(0x40|code), Function(code)
		if p.Defined() != primary[code] || s.Defined() != secondary[code] {
			t.Errorf("code %d: primary defined %v, secondary defined %v", code, p.Defined(), s.Defined())
		}
		if p.UsesFCB() != (code == 2 || code == 3) || s.UsesFCB() {
			t.Errorf("code %d: FCV column", code)
		}
		if p.HasData() != (code == 3 || code == 4) || s.HasData() {
			t.Errorf("code %d: user data", code)
		}
		for _, fn := range []Function{p, s} {
			if fn.Defined() {
				continue
			}
			h := []byte{Start0, Start1, 5, byte(fn), 1, 0, 2, 0}
			h = appendCRC(h, h)
			if _, _, err := Decode(h); !errors.Is(err, ErrInvalidFunction) {
				t.Errorf("%s: %v", fn, err)
			}
		}
	}
}

// TestSpec9_2_9_FrameErrorDetection checks clause 9.2.9 (p. 285-286): a
// frame with a wrong start, length, CRC or function code, or user data
// that does not fit its function, is discarded, and the frames after it are
// still found.
func TestSpec9_2_9_FrameErrorDetection(t *testing.T) {
	good := Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 1, Src: 2, Data: bytes.Repeat([]byte{0x5A}, 34)}
	header := func(ctrl byte) []byte {
		h := []byte{Start0, Start1, 5, ctrl, 1, 0, 2, 0}
		return appendCRC(h, h)
	}
	withData := func(ctrl byte) []byte {
		h := []byte{Start0, Start1, 6, ctrl, 1, 0, 2, 0}
		h = appendCRC(h, h)
		return appendCRC(append(h, 0xAA), []byte{0xAA})
	}
	headerCRC := stream(t, good)
	headerCRC[9] ^= 0x01
	dataCRC := stream(t, good)
	dataCRC[HeaderLength+3] ^= 0x01
	cases := map[string][]byte{
		"start":                   {0x05, 0x65, 0x05, 0xC9, 1, 0, 2, 0, 0, 0},
		"header CRC":              headerCRC,
		"data CRC":                dataCRC,
		"length below 5":          {0x05, 0x64, 0x04, 0xC9, 1, 0, 2, 0, 0, 0},
		"undefined function":      header(0xC5),
		"data on RESET":           withData(0xC0),
		"data on LINK_STATUS":     withData(0x0B),
		"no data on UNCONFIRMED":  header(0xC4),
		"no data on CONFIRMED":    header(0xF3),
		"obsolete primary code 1": header(0xC1),
	}
	for name, bad := range cases {
		if _, _, err := Decode(bad); !errors.Is(err, ErrFraming) {
			t.Errorf("%s: Decode %v, want a framing error", name, err)
		}
		in := append(bytes.Clone(bad), stream(t, good)...)
		r := NewReader(bytes.NewReader(in))
		var found bool
		for {
			f, err := r.ReadFrame()
			if errors.Is(err, ErrFraming) {
				continue
			}
			if err != nil {
				break
			}
			if !bytes.Equal(f.Data, good.Data) {
				t.Fatalf("%s: a damaged frame was accepted: %s", name, f.String())
			}
			found = true
		}
		if !found {
			t.Errorf("%s: the frame after the damaged one was lost", name)
		}
	}
}
