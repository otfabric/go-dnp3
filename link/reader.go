// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"io"
)

// Reader reads frames from a byte stream: a TCP connection, a serial port
// or the payload of UDP datagrams written into a pipe.
//
// It resynchronises after damage as IEEE 1815-2012 clause 9.2.6 requires:
// octets before a start sequence are skipped, a header with a bad CRC is
// skipped one octet at a time so that a start sequence inside it is found,
// and a frame with a bad data block CRC is discarded whole.
//
// A Reader is not safe for concurrent use.
type Reader struct {
	r   io.Reader
	buf []byte
	// start and end delimit the unread octets in buf.
	start, end int
}

// NewReader returns a Reader that reads from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r, buf: make([]byte, 2*MaxFrameLength)}
}

// ReadFrame returns the next frame.
//
// An error that wraps [ErrFraming] reports octets that were skipped or a
// frame that was discarded; the Reader stays usable and the next call
// continues after them. Any other error comes from the underlying reader
// and is returned as it is: io.EOF when the stream ended between frames,
// io.ErrUnexpectedEOF when it ended inside one.
func (r *Reader) ReadFrame() (Frame, error) {
	// Find the start sequence.
	if err := r.fill(2); err != nil {
		return Frame{}, r.eof(err)
	}
	if b := r.buf[r.start:r.end]; b[0] != Start0 || b[1] != Start1 {
		skipped := 0
		for {
			b := r.buf[r.start:r.end]
			i := bytes.Index(b, []byte{Start0, Start1})
			if i >= 0 {
				skipped += i
				r.start += i
				break
			}
			// Keep a trailing 0x05: it may be the first start octet.
			keep := 0
			if b[len(b)-1] == Start0 {
				keep = 1
			}
			skipped += len(b) - keep
			r.start = r.end - keep
			if err := r.fill(keep + 1); err != nil {
				if err == io.EOF && skipped > 0 {
					return Frame{}, framing(ErrInvalidStart, "%d octets skipped before end of stream", skipped)
				}
				return Frame{}, r.eof(err)
			}
		}
		return Frame{}, framing(ErrInvalidStart, "%d octets skipped", skipped)
	}

	if err := r.fill(HeaderLength); err != nil {
		return Frame{}, unexpected(err)
	}
	h := r.buf[r.start : r.start+HeaderLength]
	if h[2] < minLength || !checkCRC(h[:8], h[8:10]) {
		r.start++ // resynchronise inside the damaged header
		if h[2] < minLength {
			return Frame{}, framing(ErrInvalidLength, "length octet %d", h[2])
		}
		return Frame{}, framing(ErrCRC, "header")
	}
	n := EncodedLen(int(h[2]) - minLength)
	if err := r.fill(n); err != nil {
		return Frame{}, unexpected(err)
	}
	f, _, err := Decode(r.buf[r.start : r.start+n])
	r.start += n
	return f, err
}

// fill reads until at least n unread octets are buffered.
func (r *Reader) fill(n int) error {
	if r.end-r.start >= n {
		return nil
	}
	if r.start > 0 {
		r.end = copy(r.buf, r.buf[r.start:r.end])
		r.start = 0
	}
	for r.end < n {
		m, err := r.r.Read(r.buf[r.end:])
		r.end += m
		if r.end >= n {
			return nil
		}
		if err != nil {
			return err
		}
		if m == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// eof maps an end of stream in the middle of a start sequence to
// io.ErrUnexpectedEOF.
func (r *Reader) eof(err error) error {
	if err == io.EOF && r.end > r.start {
		return io.ErrUnexpectedEOF
	}
	return err
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
