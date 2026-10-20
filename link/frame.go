// SPDX-License-Identifier: MIT

package link

import (
	"errors"
	"fmt"
)

const (
	// Start0 and Start1 are the two start octets of every frame.
	Start0 = 0x05
	Start1 = 0x64

	// HeaderLength is the size of the header block on the wire: start
	// octets, length, control, destination, source and the header CRC.
	HeaderLength = 10

	// MaxUserData is the largest user data a frame carries: 255 for the
	// length octet minus the five octets of control and addresses.
	MaxUserData = 250

	// BlockSize is the number of user data octets protected by one CRC.
	BlockSize = 16

	// MaxFrameLength is the largest frame on the wire: the header plus
	// 250 octets of user data in sixteen blocks, each with its CRC.
	MaxFrameLength = HeaderLength + MaxUserData + 2*((MaxUserData+BlockSize-1)/BlockSize)

	minLength = 5
)

// Framing errors returned by [Decode] and [Reader.ReadFrame]. Each wraps
// [ErrFraming] as well, so a caller can tell a damaged frame (discard it and
// go on) from a failing transport with errors.Is(err, ErrFraming).
var (
	// ErrFraming is wrapped by every error that reports a damaged or
	// invalid frame. The stream itself is still usable.
	ErrFraming = errors.New("link: framing error")

	// ErrInvalidStart reports a frame that does not begin with 0x05 0x64.
	ErrInvalidStart = errors.New("link: invalid start octets")

	// ErrInvalidLength reports a length octet below 5, or a frame whose
	// length does not fit its function.
	ErrInvalidLength = errors.New("link: invalid length")

	// ErrCRC reports a header or data block whose CRC does not match.
	ErrCRC = errors.New("link: CRC error")

	// ErrInvalidFunction reports a function code the standard does not
	// define for the frame's direction (primary or secondary).
	ErrInvalidFunction = errors.New("link: invalid function code")

	// ErrShortBuffer reports a buffer that holds only part of a frame.
	ErrShortBuffer = errors.New("link: incomplete frame")
)

func framing(err error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: "+format, append([]any{ErrFraming, err}, args...)...)
}

// Frame is one link layer frame (FT3 format).
type Frame struct {
	// Dir is the DIR bit: set when the frame is sent by a master.
	Dir bool

	// Function is the function code together with the PRM bit: the
	// Primary* constants for frames that initiate a transaction, the
	// Secondary* constants for the replies.
	Function Function

	// FCB is the frame count bit of a primary frame.
	FCB bool

	// FCV is the frame count valid bit of a primary frame. It is set for
	// the functions that use the frame count bit
	// ([PrimaryTestLinkStates] and [PrimaryConfirmedUserData]).
	FCV bool

	// DFC is the data flow control bit of a secondary frame: the
	// secondary station cannot accept further data.
	DFC bool

	// Dest and Src are the destination and source addresses.
	Dest, Src Address

	// Data is the user data, 1..250 octets for the user data functions and
	// empty for all others.
	Data []byte
}

// Control returns the control octet of f.
func (f *Frame) Control() byte {
	c := byte(f.Function)
	if f.Dir {
		c |= 0x80
	}
	if f.Function.Primary() {
		if f.FCB {
			c |= 0x20
		}
		if f.FCV {
			c |= 0x10
		}
	} else if f.DFC {
		c |= 0x10
	}
	return c
}

// setControl sets the control fields of f from c.
func (f *Frame) setControl(c byte) {
	f.Dir = c&0x80 != 0
	f.Function = Function(c & 0x4F)
	if f.Function.Primary() {
		f.FCB = c&0x20 != 0
		f.FCV = c&0x10 != 0
	} else {
		f.DFC = c&0x10 != 0
	}
}

// Validate reports whether f can be encoded: a defined function code and a
// user data length the function allows.
func (f *Frame) Validate() error {
	if !f.Function.Defined() {
		return framing(ErrInvalidFunction, "%s", f.Function)
	}
	n := len(f.Data)
	switch {
	case n > MaxUserData:
		return framing(ErrInvalidLength, "%d octets of user data, at most %d", n, MaxUserData)
	case f.Function.HasData() && n == 0:
		return framing(ErrInvalidLength, "%s without user data", f.Function)
	case !f.Function.HasData() && n > 0:
		return framing(ErrInvalidLength, "%s with %d octets of user data", f.Function, n)
	}
	return nil
}

// EncodedLen returns the length of a frame carrying n octets of user data.
func EncodedLen(n int) int {
	return HeaderLength + n + 2*((n+BlockSize-1)/BlockSize)
}

// Encode returns the wire encoding of f.
func (f *Frame) Encode() ([]byte, error) {
	return f.AppendEncode(make([]byte, 0, EncodedLen(len(f.Data))))
}

// AppendEncode appends the wire encoding of f to b.
func (f *Frame) AppendEncode(b []byte) ([]byte, error) {
	if err := f.Validate(); err != nil {
		return b, err
	}
	start := len(b)
	b = append(b, Start0, Start1, byte(minLength+len(f.Data)), f.Control(),
		byte(f.Dest), byte(f.Dest>>8), byte(f.Src), byte(f.Src>>8))
	b = appendCRC(b, b[start:])
	for d := f.Data; len(d) > 0; {
		n := min(len(d), BlockSize)
		b = append(b, d[:n]...)
		b = appendCRC(b, d[:n])
		d = d[n:]
	}
	return b, nil
}

// FrameLength returns the length on the wire of the frame whose header
// begins b, from its length octet. b must hold at least three octets.
func FrameLength(b []byte) (int, error) {
	if len(b) < 3 {
		return 0, framing(ErrShortBuffer, "%d octets", len(b))
	}
	if b[0] != Start0 || b[1] != Start1 {
		return 0, framing(ErrInvalidStart, "% x", b[:2])
	}
	if b[2] < minLength {
		return 0, framing(ErrInvalidLength, "length octet %d", b[2])
	}
	return EncodedLen(int(b[2]) - minLength), nil
}

// Decode decodes the frame at the start of b and returns it with the
// number of octets it occupies. The user data of the frame is a new slice,
// not a view into b.
//
// Every error wraps [ErrFraming]; a buffer that holds only part of a frame
// also wraps [ErrShortBuffer].
func Decode(b []byte) (Frame, int, error) {
	var f Frame
	if len(b) < HeaderLength {
		if len(b) >= 2 && (b[0] != Start0 || b[1] != Start1) {
			return f, 0, framing(ErrInvalidStart, "% x", b[:2])
		}
		return f, 0, framing(ErrShortBuffer, "%d octets", len(b))
	}
	n, err := FrameLength(b)
	if err != nil {
		return f, 0, err
	}
	if !checkCRC(b[:8], b[8:10]) {
		return f, 0, framing(ErrCRC, "header")
	}
	if len(b) < n {
		return f, 0, framing(ErrShortBuffer, "%d of %d octets", len(b), n)
	}
	f.setControl(b[3])
	f.Dest = Address(b[4]) | Address(b[5])<<8
	f.Src = Address(b[6]) | Address(b[7])<<8
	if ud := int(b[2]) - minLength; ud > 0 {
		f.Data = make([]byte, 0, ud)
		for p, i := b[HeaderLength:n], 0; len(p) > 0; i++ {
			bl := min(len(p)-2, BlockSize)
			if !checkCRC(p[:bl], p[bl:bl+2]) {
				return Frame{}, 0, framing(ErrCRC, "data block %d", i)
			}
			f.Data = append(f.Data, p[:bl]...)
			p = p[bl+2:]
		}
	}
	if err := f.Validate(); err != nil {
		return Frame{}, 0, err
	}
	return f, n, nil
}

// String returns a one-line description for logs, for example
// "PRI CONFIRMED_USER_DATA dir fcb fcv 1024->1 len=17".
func (f *Frame) String() string {
	s := "SEC "
	if f.Function.Primary() {
		s = "PRI "
	}
	s += f.Function.String()
	if f.Dir {
		s += " dir"
	}
	if f.Function.Primary() {
		if f.FCB {
			s += " fcb"
		}
		if f.FCV {
			s += " fcv"
		}
	} else if f.DFC {
		s += " dfc"
	}
	return fmt.Sprintf("%s %d->%d len=%d", s, f.Src, f.Dest, len(f.Data))
}
