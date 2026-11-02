// SPDX-License-Identifier: MIT

package app

import (
	"time"
)

// The status of requested operation object of ACTIVATE_CONFIG (g91v1,
// IEEE 1815-2012 Annex A, group 91): a time delay (UINT32, milliseconds)
// and a count (UINT8) of status entries, each a length (UINT8, the octets
// of the status code and the text), a status code (UINT8) and a text.
// The object delimits itself, so it is sent with a count qualifier
// (0x07, one object) as well as with a free-format one.
const (
	activationHeaderSize = 5   // time delay and count
	maxActivationText    = 254 // the length octet counts the status code too
	maxActivationResults = 255
)

// ActivateConfigStatus is the content of a status of requested operation
// object (g91v1): the outstation's answer to ACTIVATE_CONFIG. [Decode]
// returns g91v1 objects as [Raw]; [ParseActivateConfigStatus] reads their
// data and [ActivateConfigStatus.Raw] makes one.
type ActivateConfigStatus struct {
	// Delay is the time the outstation needs before the activated
	// configuration is in effect, in milliseconds on the wire.
	Delay time.Duration
	// Results are the status entries, usually one per object of the
	// request: at most 255.
	Results []ActivateConfigResult
}

// ActivateConfigResult is one status entry of a g91v1 object.
type ActivateConfigResult struct {
	// Code is the status code; 0 is success.
	Code uint8
	// Text is optional text about the status: at most 254 octets.
	Text string
}

// activationLen returns the octets of the g91v1 object at the start of b.
func activationLen(b []byte) (int, error) {
	if len(b) < activationHeaderSize {
		return 0, truncated("g91v1: %d octets, want at least %d", len(b), activationHeaderSize)
	}
	n := int(b[4])
	p := activationHeaderSize
	for i := range n {
		if p >= len(b) {
			return 0, truncated("g91v1: status %d of %d", i+1, n)
		}
		l := int(b[p])
		if l == 0 {
			return 0, malformed("g91v1: status %d of length 0, without a status code", i+1)
		}
		if len(b)-p-1 < l {
			return 0, truncated("g91v1: status %d of %d octets, %d left", i+1, l, len(b)-p-1)
		}
		p += 1 + l
	}
	return p, nil
}

// ParseActivateConfigStatus reads the data of one g91v1 object (the Data
// of the [Raw] that [Decode] returns). It fails with [ErrMalformed] when
// the data are not exactly one status of requested operation.
func ParseActivateConfigStatus(data []byte) (ActivateConfigStatus, error) {
	n, err := activationLen(data)
	if err != nil {
		return ActivateConfigStatus{}, err
	}
	if n != len(data) {
		return ActivateConfigStatus{}, malformed("g91v1: %d octets after the status entries", len(data)-n)
	}
	r := reader{b: data}
	s := ActivateConfigStatus{Delay: time.Duration(r.u32()) * time.Millisecond}
	count := int(r.u8())
	if count > 0 {
		s.Results = make([]ActivateConfigResult, count)
	}
	for i := range s.Results {
		l := int(r.u8())
		s.Results[i].Code = r.u8()
		s.Results[i].Text = string(r.bytes(l - 1))
	}
	return s, r.done()
}

// Raw encodes s as the data of a g91v1 object, to send for example as
// app.Counted(app.G91V1, raw). It fails with [ErrInvalidValue] when Delay
// is negative or does not fit 32 bits of milliseconds, when there are
// more than 255 results, or when a text is longer than 254 octets.
func (s ActivateConfigStatus) Raw() (Raw, error) {
	ms := s.Delay / time.Millisecond
	if s.Delay < 0 || ms > 0xFFFFFFFF {
		return Raw{}, invalid("g91v1 time delay %v", s.Delay)
	}
	if len(s.Results) > maxActivationResults {
		return Raw{}, invalid("g91v1 with %d status entries, at most %d", len(s.Results), maxActivationResults)
	}
	b := le32(make([]byte, 0, activationHeaderSize+2*len(s.Results)), uint32(ms))
	b = append(b, byte(len(s.Results)))
	for i, e := range s.Results {
		if len(e.Text) > maxActivationText {
			return Raw{}, invalid("g91v1 status %d: text of %d octets, at most %d", i+1, len(e.Text), maxActivationText)
		}
		b = append(b, byte(len(e.Text)+1), e.Code)
		b = append(b, e.Text...)
	}
	return Raw{Data: b}, nil
}
