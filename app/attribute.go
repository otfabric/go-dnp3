// SPDX-License-Identifier: MIT

package app

import (
	"encoding/binary"
	"fmt"
	"math"
)

// AttrType is the data type code of a device attribute (IEEE 1815-2012
// Table 11-11).
type AttrType uint8

// Attribute data types.
const (
	AttrVisibleString AttrType = 1
	AttrUnsignedInt   AttrType = 2
	AttrSignedInt     AttrType = 3
	AttrFloat         AttrType = 4
	AttrOctetString   AttrType = 5
	AttrBitString     AttrType = 6
	AttrTime          AttrType = 7
	// AttrList is the list of attribute variations returned for g0v255;
	// AttrExtList is the same with a length above 255 (the length octet
	// holds length-256).
	AttrList    AttrType = 254
	AttrExtList AttrType = 255
)

// String returns the abbreviation of the standard, for example "VSTR".
func (t AttrType) String() string {
	switch t {
	case AttrVisibleString:
		return "VSTR"
	case AttrUnsignedInt:
		return "UINT"
	case AttrSignedInt:
		return "INT"
	case AttrFloat:
		return "FLT"
	case AttrOctetString:
		return "OSTR"
	case AttrBitString:
		return "BSTR"
	case AttrTime:
		return "TIME"
	case AttrList:
		return "LIST"
	case AttrExtList:
		return "EXLIST"
	default:
		return fmt.Sprintf("ATTR_TYPE(%d)", uint8(t))
	}
}

// Standard device attribute variations of group 0 (set 0).
const (
	AttrConfigID                    uint8 = 196
	AttrConfigVersion               uint8 = 197
	AttrConfigBuildDate             uint8 = 198
	AttrConfigLastChangeDate        uint8 = 199
	AttrConfigDigest                uint8 = 200
	AttrConfigDigestAlgorithm       uint8 = 201
	AttrMasterResourceID            uint8 = 202
	AttrDeviceAltitude              uint8 = 203
	AttrDeviceLongitude             uint8 = 204
	AttrDeviceLatitude              uint8 = 205
	AttrSecondaryOperatorName       uint8 = 206
	AttrPrimaryOperatorName         uint8 = 207
	AttrSystemName                  uint8 = 208
	AttrSecureAuthVersion           uint8 = 209
	AttrNumSecurityStats            uint8 = 210
	AttrUserSpecificAttributes      uint8 = 211
	AttrNumMasterDataSetProtos      uint8 = 212
	AttrNumOutstationDataSetProtos  uint8 = 213
	AttrNumMasterDataSets           uint8 = 214
	AttrNumOutstationDataSets       uint8 = 215
	AttrMaxBinaryOutputsPerRequest  uint8 = 216
	AttrLocalTimingAccuracy         uint8 = 217
	AttrTimeAccuracyDuration        uint8 = 218
	AttrSupportsAnalogOutputEvents  uint8 = 219
	AttrMaxAnalogOutputIndex        uint8 = 220
	AttrNumAnalogOutputs            uint8 = 221
	AttrSupportsBinaryOutputEvents  uint8 = 222
	AttrMaxBinaryOutputIndex        uint8 = 223
	AttrNumBinaryOutputs            uint8 = 224
	AttrSupportsFrozenCounterEvents uint8 = 225
	AttrSupportsFrozenCounters      uint8 = 226
	AttrSupportsCounterEvents       uint8 = 227
	AttrMaxCounterIndex             uint8 = 228
	AttrNumCounters                 uint8 = 229
	AttrSupportsFrozenAnalogInputs  uint8 = 230
	AttrSupportsAnalogInputEvents   uint8 = 231
	AttrMaxAnalogInputIndex         uint8 = 232
	AttrNumAnalogInputs             uint8 = 233
	AttrSupportsDoubleBitEvents     uint8 = 234
	AttrMaxDoubleBitIndex           uint8 = 235
	AttrNumDoubleBitInputs          uint8 = 236
	AttrSupportsBinaryInputEvents   uint8 = 237
	AttrMaxBinaryInputIndex         uint8 = 238
	AttrNumBinaryInputs             uint8 = 239
	AttrMaxTxFragmentSize           uint8 = 240
	AttrMaxRxFragmentSize           uint8 = 241
	AttrSoftwareVersion             uint8 = 242
	AttrHardwareVersion             uint8 = 243
	AttrOwnerName                   uint8 = 244
	AttrUserLocation                uint8 = 245
	AttrUserID                      uint8 = 246
	AttrUserDeviceName              uint8 = 247
	AttrSerialNumber                uint8 = 248
	AttrSubsetAndConformance        uint8 = 249
	AttrProductNameAndModel         uint8 = 250
	AttrManufacturerName            uint8 = 252
	// AttrAllAttributes (g0v254) requests every attribute; it carries no
	// object.
	AttrAllAttributes uint8 = 254
	// AttrListOfVariations (g0v255) is the list of supported attribute
	// variations.
	AttrListOfVariations uint8 = 255
)

// Attribute is a device attribute (group 0): a data type code and the
// raw value. Use the constructors and accessors to work with typed values.
type Attribute struct {
	Type AttrType
	// Data is the encoded value: the string octets, the little-endian
	// integer of 1, 2 or 4 octets, the IEEE 754 value of 4 or 8 octets,
	// the 6-octet time, or the list of (variation, properties) pairs.
	Data []byte
}

func (Attribute) isValue() {}

// StringAttribute returns a visible string attribute.
func StringAttribute(s string) Attribute {
	return Attribute{Type: AttrVisibleString, Data: []byte(s)}
}

// UintAttribute returns an unsigned integer attribute in the smallest
// width that holds v.
func UintAttribute(v uint32) Attribute {
	switch {
	case v <= 0xFF:
		return Attribute{Type: AttrUnsignedInt, Data: []byte{byte(v)}}
	case v <= 0xFFFF:
		return Attribute{Type: AttrUnsignedInt, Data: binary.LittleEndian.AppendUint16(nil, uint16(v))}
	default:
		return Attribute{Type: AttrUnsignedInt, Data: binary.LittleEndian.AppendUint32(nil, v)}
	}
}

// IntAttribute returns a signed integer attribute of four octets.
func IntAttribute(v int32) Attribute {
	return Attribute{Type: AttrSignedInt, Data: binary.LittleEndian.AppendUint32(nil, uint32(v))}
}

// FloatAttribute returns a floating-point attribute of eight octets.
func FloatAttribute(v float64) Attribute {
	return Attribute{Type: AttrFloat, Data: binary.LittleEndian.AppendUint64(nil, math.Float64bits(v))}
}

// TimeAttribute returns a DNP3 time attribute.
func TimeAttribute(t Timestamp) Attribute {
	return Attribute{Type: AttrTime, Data: le48(nil, t)}
}

// AttributeListEntry is one entry of the list of attribute variations.
type AttributeListEntry struct {
	Variation uint8
	// Writable reports whether the master may write the attribute.
	Writable bool
}

// ListAttribute returns the list of attribute variations (the value of
// g0v255).
func ListAttribute(entries ...AttributeListEntry) Attribute {
	b := make([]byte, 0, 2*len(entries))
	for _, e := range entries {
		p := byte(0)
		if e.Writable {
			p = 1
		}
		b = append(b, e.Variation, p)
	}
	t := AttrList
	if len(b) > 255 {
		t = AttrExtList
	}
	return Attribute{Type: t, Data: b}
}

// Text returns the value of a visible string or octet string attribute.
func (a Attribute) Text() string { return string(a.Data) }

// Uint returns the value of an unsigned integer attribute.
func (a Attribute) Uint() (uint32, error) {
	if a.Type != AttrUnsignedInt {
		return 0, invalid("attribute is %s, not UINT", a.Type)
	}
	switch len(a.Data) {
	case 1:
		return uint32(a.Data[0]), nil
	case 2:
		return uint32(binary.LittleEndian.Uint16(a.Data)), nil
	case 4:
		return binary.LittleEndian.Uint32(a.Data), nil
	default:
		return 0, invalid("UINT attribute of %d octets", len(a.Data))
	}
}

// Int returns the value of a signed integer attribute.
func (a Attribute) Int() (int32, error) {
	if a.Type != AttrSignedInt {
		return 0, invalid("attribute is %s, not INT", a.Type)
	}
	switch len(a.Data) {
	case 1:
		return int32(int8(a.Data[0])), nil
	case 2:
		return int32(int16(binary.LittleEndian.Uint16(a.Data))), nil
	case 4:
		return int32(binary.LittleEndian.Uint32(a.Data)), nil
	default:
		return 0, invalid("INT attribute of %d octets", len(a.Data))
	}
}

// Float returns the value of a floating-point attribute.
func (a Attribute) Float() (float64, error) {
	if a.Type != AttrFloat {
		return 0, invalid("attribute is %s, not FLT", a.Type)
	}
	switch len(a.Data) {
	case 4:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(a.Data))), nil
	case 8:
		return math.Float64frombits(binary.LittleEndian.Uint64(a.Data)), nil
	default:
		return 0, invalid("FLT attribute of %d octets", len(a.Data))
	}
}

// List returns the entries of a list of attribute variations.
func (a Attribute) List() ([]AttributeListEntry, error) {
	if a.Type != AttrList && a.Type != AttrExtList {
		return nil, invalid("attribute is %s, not a list", a.Type)
	}
	if len(a.Data)%2 != 0 {
		return nil, invalid("attribute list of %d octets", len(a.Data))
	}
	out := make([]AttributeListEntry, 0, len(a.Data)/2)
	for i := 0; i < len(a.Data); i += 2 {
		out = append(out, AttributeListEntry{Variation: a.Data[i], Writable: a.Data[i+1]&1 != 0})
	}
	return out, nil
}

// decodeAttribute reads one self-sized attribute from b and returns it
// with the octets consumed.
func decodeAttribute(b []byte) (Attribute, int, error) {
	if len(b) < 2 {
		return Attribute{}, 0, truncated("attribute header")
	}
	t, n := AttrType(b[0]), int(b[1])
	if t == AttrExtList {
		n += 256
	}
	if len(b) < 2+n {
		return Attribute{}, 0, truncated("attribute value of %d octets", n)
	}
	return Attribute{Type: t, Data: clone(b[2 : 2+n])}, 2 + n, nil
}

func encodeAttribute(b []byte, a Attribute) ([]byte, error) {
	n := len(a.Data)
	switch {
	case a.Type == AttrExtList && (n < 256 || n > 511):
		return b, invalid("extended attribute list of %d octets", n)
	case a.Type != AttrExtList && n > 255:
		return b, invalid("attribute of %d octets", n)
	case a.Type == AttrExtList:
		n -= 256
	}
	b = append(b, byte(a.Type), byte(n))
	return append(b, a.Data...), nil
}
