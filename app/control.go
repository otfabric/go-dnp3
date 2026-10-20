// SPDX-License-Identifier: MIT

package app

import "fmt"

// Control is the application control octet (IEEE 1815-2012
// clause 4.2.2.4).
type Control struct {
	// FIR and FIN mark the first and the final fragment of a message.
	FIR, FIN bool
	// CON requests an application confirmation of this fragment.
	CON bool
	// UNS marks an unsolicited response, and its confirmation.
	UNS bool
	// Seq is the four-bit sequence number, 0..15.
	Seq uint8
}

// SingleControl returns the control octet of a single-fragment message with the
// given sequence number.
func SingleControl(seq uint8) Control { return Control{FIR: true, FIN: true, Seq: seq & 0x0F} }

// Byte returns the encoded control octet.
func (c Control) Byte() byte {
	b := c.Seq & 0x0F
	if c.FIR {
		b |= 0x80
	}
	if c.FIN {
		b |= 0x40
	}
	if c.CON {
		b |= 0x20
	}
	if c.UNS {
		b |= 0x10
	}
	return b
}

// ParseControl decodes a control octet.
func ParseControl(b byte) Control {
	return Control{FIR: b&0x80 != 0, FIN: b&0x40 != 0, CON: b&0x20 != 0, UNS: b&0x10 != 0, Seq: b & 0x0F}
}

// String returns, for example, "FIR FIN CON seq=3".
func (c Control) String() string {
	s := ""
	if c.FIR {
		s += "FIR "
	}
	if c.FIN {
		s += "FIN "
	}
	if c.CON {
		s += "CON "
	}
	if c.UNS {
		s += "UNS "
	}
	return fmt.Sprintf("%sseq=%d", s, c.Seq)
}

// NextSeq returns the sequence number that follows seq, modulo 16.
func NextSeq(seq uint8) uint8 { return (seq + 1) & 0x0F }
