// SPDX-License-Identifier: MIT

package link

// The DNP3 CRC (IEEE 1815-2012 clause 9.2.5): polynomial
// x^16+x^13+x^12+x^11+x^10+x^8+x^6+x^5+x^2+1 (0x3D65), processed least
// significant bit first, initial value 0, result complemented, transmitted
// low octet first.
const crcPolyReflected = 0xA6BC

var crcTable = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ crcPolyReflected
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}()

// CRC returns the DNP3 CRC of b.
func CRC(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = c>>8 ^ crcTable[byte(c)^x]
	}
	return ^c
}

// appendCRC appends the CRC of block to b, low octet first.
func appendCRC(b, block []byte) []byte {
	c := CRC(block)
	return append(b, byte(c), byte(c>>8))
}

// checkCRC reports whether the two octets after block hold its CRC.
func checkCRC(block []byte, crc []byte) bool {
	c := CRC(block)
	return crc[0] == byte(c) && crc[1] == byte(c>>8)
}
