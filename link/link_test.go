// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Reset of link states from master 1024 to outstation 1, the example frame
// found in most DNP3 introductions.
const resetLinkHex = "05 64 05 C0 01 00 00 04 E9 21"

func TestCRCKnownVector(t *testing.T) {
	b := unhex(t, resetLinkHex)
	if got := CRC(b[:8]); got != 0x21E9 {
		t.Fatalf("CRC = %#04x, want 0x21e9", got)
	}
}

func TestEncodeKnownFrame(t *testing.T) {
	f := Frame{Dir: true, Function: PrimaryResetLinkStates, Dest: 1, Src: 1024}
	got, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, resetLinkHex); !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	d, n, err := Decode(got)
	if err != nil || n != len(got) {
		t.Fatalf("decode: n=%d err=%v", n, err)
	}
	if d.String() != "PRI RESET_LINK_STATES dir 1024->1 len=0" {
		t.Fatalf("String = %q", d.String())
	}
}

func TestRoundTripDataLengths(t *testing.T) {
	for n := 1; n <= MaxUserData; n++ {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + n)
		}
		f := Frame{Function: PrimaryUnconfirmedUserData, FCB: false, Dest: 0xFFEF, Src: 3, Data: data}
		b, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != EncodedLen(n) {
			t.Fatalf("n=%d: len %d, want %d", n, len(b), EncodedLen(n))
		}
		got, m, err := Decode(b)
		if err != nil || m != len(b) {
			t.Fatalf("n=%d: decode m=%d err=%v", n, m, err)
		}
		if !bytes.Equal(got.Data, data) || got.Dest != f.Dest || got.Src != f.Src || got.Function != f.Function {
			t.Fatalf("n=%d: mismatch %v", n, got.String())
		}
	}
	if EncodedLen(MaxUserData) != MaxFrameLength || MaxFrameLength != 292 {
		t.Fatalf("MaxFrameLength = %d", MaxFrameLength)
	}
}

func TestControlBits(t *testing.T) {
	cases := []struct {
		f    Frame
		ctrl byte
	}{
		{Frame{Dir: true, Function: PrimaryConfirmedUserData, FCB: true, FCV: true, Data: []byte{0}}, 0xF3},
		{Frame{Dir: true, Function: PrimaryTestLinkStates, FCV: true}, 0xD2},
		{Frame{Function: PrimaryRequestLinkStatus}, 0x49},
		{Frame{Function: SecondaryAck}, 0x00},
		{Frame{Dir: true, Function: SecondaryLinkStatus, DFC: true}, 0x9B},
		{Frame{Function: SecondaryNotSupported}, 0x0F},
		{Frame{Function: SecondaryNack}, 0x01},
	}
	for _, c := range cases {
		if got := c.f.Control(); got != c.ctrl {
			t.Errorf("%s: control %#02x, want %#02x", c.f.String(), got, c.ctrl)
		}
		b, err := c.f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		d, _, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if d.Control() != c.ctrl || d.FCB != c.f.FCB || d.FCV != c.f.FCV || d.DFC != c.f.DFC || d.Dir != c.f.Dir {
			t.Errorf("%s: decoded %s", c.f.String(), d.String())
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []Frame{
		{Function: PrimaryConfirmedUserData},
		{Function: PrimaryResetLinkStates, Data: []byte{1}},
		{Function: SecondaryAck, Data: []byte{1}},
		{Function: 0x40 | 1},
		{Function: 5},
		{Function: PrimaryUnconfirmedUserData, Data: make([]byte, MaxUserData+1)},
	}
	for _, f := range bad {
		if _, err := f.Encode(); !errors.Is(err, ErrFraming) {
			t.Errorf("%s: err = %v, want ErrFraming", f.String(), err)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	good, _ := (&Frame{Function: PrimaryUnconfirmedUserData, Data: bytes.Repeat([]byte{0xAA}, 20)}).Encode()

	hdr := bytes.Clone(good)
	hdr[4] ^= 1
	data := bytes.Clone(good)
	data[len(data)-3] ^= 1
	short := good[:len(good)-1]
	start := bytes.Clone(good)
	start[1] = 0x65
	length := unhex(t, "05 64 04 C0 01 00 00 04 00 00")
	// A header with a valid CRC but a function code the standard does not define.
	fn := []byte{0x05, 0x64, 0x05, 0x41, 1, 0, 0, 4}
	fn = appendCRC(fn, fn)

	cases := []struct {
		name string
		b    []byte
		want error
	}{
		{"header crc", hdr, ErrCRC},
		{"data crc", data, ErrCRC},
		{"short", short, ErrShortBuffer},
		{"tiny", good[:4], ErrShortBuffer},
		{"start", start, ErrInvalidStart},
		{"length", length, ErrInvalidLength},
		{"function", fn, ErrInvalidFunction},
	}
	for _, c := range cases {
		_, _, err := Decode(c.b)
		if !errors.Is(err, c.want) || !errors.Is(err, ErrFraming) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestAddress(t *testing.T) {
	// IEEE 1815: 0xFFFD no confirmation, 0xFFFE mandatory, 0xFFFF optional.
	if BroadcastNoConfirm != 0xFFFD || BroadcastConfirm != 0xFFFE || BroadcastOptionalConfirm != 0xFFFF {
		t.Fatal("broadcast addresses")
	}
	if !BroadcastConfirm.Broadcast() || !BroadcastNoConfirm.Broadcast() || SelfAddress.Broadcast() {
		t.Error("Broadcast")
	}
	if !Address(0xFFF0).Reserved() || SelfAddress.Reserved() || MaxStationAddress.Reserved() {
		t.Error("Reserved")
	}
}

func TestFunctionStrings(t *testing.T) {
	for f, want := range map[Function]string{
		PrimaryResetLinkStates: "RESET_LINK_STATES", PrimaryTestLinkStates: "TEST_LINK_STATES",
		PrimaryConfirmedUserData: "CONFIRMED_USER_DATA", PrimaryUnconfirmedUserData: "UNCONFIRMED_USER_DATA",
		PrimaryRequestLinkStatus: "REQUEST_LINK_STATUS", SecondaryAck: "ACK", SecondaryNack: "NACK",
		SecondaryLinkStatus: "LINK_STATUS", SecondaryNotSupported: "NOT_SUPPORTED",
		0x40 | 7: "PRIMARY(7)", 6: "SECONDARY(6)",
	} {
		if f.String() != want {
			t.Errorf("%#x: %q, want %q", uint8(f), f.String(), want)
		}
	}
	if !PrimaryConfirmedUserData.UsesFCB() || PrimaryUnconfirmedUserData.UsesFCB() {
		t.Error("UsesFCB")
	}
}

// stream concatenates the encodings of frames.
func stream(t testing.TB, frames ...Frame) []byte {
	t.Helper()
	var b []byte
	for _, f := range frames {
		var err error
		if b, err = f.AppendEncode(b); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestReaderResynchronises(t *testing.T) {
	f1 := Frame{Dir: true, Function: PrimaryUnconfirmedUserData, Dest: 1, Src: 2, Data: []byte("first frame, longer than one block")}
	f2 := Frame{Function: SecondaryAck, Dest: 2, Src: 1}
	f3 := Frame{Function: PrimaryUnconfirmedUserData, Dest: 1, Src: 2, Data: []byte{1, 2, 3}}

	damaged := stream(t, f2)
	damaged[3] ^= 0x80 // header CRC no longer matches

	badData := stream(t, f3)
	badData[len(badData)-1] ^= 0xFF

	var in []byte
	in = append(in, 0x00, 0x05, 0x05, 0x99) // garbage, with lone start octets
	in = append(in, stream(t, f1)...)
	in = append(in, damaged...)
	in = append(in, badData...)
	in = append(in, stream(t, f2, f3)...)
	in = append(in, 0x05) // a dangling start octet at the end

	for name, src := range map[string]io.Reader{
		"whole":   bytes.NewReader(in),
		"onebyte": iotest.OneByteReader(bytes.NewReader(in)),
		"half":    iotest.HalfReader(bytes.NewReader(in)),
	} {
		t.Run(name, func(t *testing.T) {
			r := NewReader(src)
			var got []Frame
			var framingErrs int
			for {
				f, err := r.ReadFrame()
				if err != nil {
					if errors.Is(err, ErrFraming) {
						framingErrs++
						continue
					}
					if err != io.ErrUnexpectedEOF {
						t.Fatalf("final error %v, want io.ErrUnexpectedEOF", err)
					}
					break
				}
				got = append(got, f)
			}
			if len(got) != 3 || !bytes.Equal(got[0].Data, f1.Data) || got[1].Function != SecondaryAck || !bytes.Equal(got[2].Data, f3.Data) {
				for _, f := range got {
					t.Log(f.String())
				}
				t.Fatalf("got %d frames", len(got))
			}
			if framingErrs < 3 {
				t.Fatalf("framing errors = %d, want at least 3", framingErrs)
			}
		})
	}
}

func TestReaderEOF(t *testing.T) {
	r := NewReader(bytes.NewReader(nil))
	if _, err := r.ReadFrame(); err != io.EOF {
		t.Fatalf("empty stream: %v, want io.EOF", err)
	}
	b := stream(t, Frame{Function: PrimaryUnconfirmedUserData, Data: []byte{1, 2, 3}})
	r = NewReader(bytes.NewReader(b[:12]))
	if _, err := r.ReadFrame(); err != io.ErrUnexpectedEOF {
		t.Fatalf("cut frame: %v, want io.ErrUnexpectedEOF", err)
	}
	r = NewReader(bytes.NewReader([]byte{1, 2, 3}))
	if _, err := r.ReadFrame(); !errors.Is(err, ErrInvalidStart) {
		t.Fatalf("garbage then EOF: %v", err)
	}
	if _, err := r.ReadFrame(); err != io.EOF {
		t.Fatalf("after garbage: %v, want io.EOF", err)
	}
	r = NewReader(iotest.ErrReader(io.ErrClosedPipe))
	if _, err := r.ReadFrame(); err != io.ErrClosedPipe {
		t.Fatalf("transport error: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(unhex(f, resetLinkHex))
	f.Add(stream(f, Frame{Function: PrimaryConfirmedUserData, FCV: true, Data: bytes.Repeat([]byte{7}, 40)}))
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, n, err := Decode(b)
		if err != nil {
			return
		}
		re, err := fr.Encode()
		if err != nil {
			t.Fatalf("decoded frame does not encode: %v", err)
		}
		if !bytes.Equal(re, b[:n]) {
			// Only the reserved control bit of a secondary frame (0x20)
			// may differ: it is ignored on decode.
			if len(re) != n || re[3] != b[3]&^0x20 {
				t.Fatalf("re-encode differs:\n% x\n% x", re, b[:n])
			}
		}
	})
}

func FuzzReader(f *testing.F) {
	f.Add(stream(f, Frame{Function: PrimaryUnconfirmedUserData, Data: []byte{1}}, Frame{Function: SecondaryAck}))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReader(bytes.NewReader(b))
		for i := 0; ; i++ {
			if i > len(b)+1 {
				t.Fatal("reader makes no progress")
			}
			_, err := r.ReadFrame()
			if err != nil && !errors.Is(err, ErrFraming) {
				return
			}
		}
	})
}
