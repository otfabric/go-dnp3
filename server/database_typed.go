// SPDX-License-Identifier: MIT

package server

import "github.com/otfabric/go-dnp3/app"

// Typed forms of Add and Update, one per point type. Updates use
// EventOnChange; use Update or Batch for another mode.

// AddBinaryInput adds a binary input (group 1, events group 2).
func (db *Database) AddBinaryInput(index uint32, cfg PointConfig, v app.Binary) error {
	return db.Add(BinaryInput, index, cfg, v)
}

// AddDoubleBitInput adds a double-bit binary input (groups 3 and 4).
func (db *Database) AddDoubleBitInput(index uint32, cfg PointConfig, v app.DoubleBitBinary) error {
	return db.Add(DoubleBitInput, index, cfg, v)
}

// AddBinaryOutput adds a binary output status (groups 10 and 11).
func (db *Database) AddBinaryOutput(index uint32, cfg PointConfig, v app.Binary) error {
	return db.Add(BinaryOutput, index, cfg, v)
}

// AddCounter adds a counter (groups 20 and 22).
func (db *Database) AddCounter(index uint32, cfg PointConfig, v app.Counter) error {
	return db.Add(Counter, index, cfg, v)
}

// AddFrozenCounter adds a frozen counter (groups 21 and 23). A freeze
// request copies the counter of the same index into it.
func (db *Database) AddFrozenCounter(index uint32, cfg PointConfig, v app.Counter) error {
	return db.Add(FrozenCounter, index, cfg, v)
}

// AddAnalogInput adds an analog input (groups 30 and 32).
func (db *Database) AddAnalogInput(index uint32, cfg PointConfig, v app.Analog) error {
	return db.Add(AnalogInput, index, cfg, v)
}

// AddFrozenAnalogInput adds a frozen analog input (groups 31 and 33).
func (db *Database) AddFrozenAnalogInput(index uint32, cfg PointConfig, v app.Analog) error {
	return db.Add(FrozenAnalogInput, index, cfg, v)
}

// AddAnalogOutput adds an analog output status (groups 40 and 42).
func (db *Database) AddAnalogOutput(index uint32, cfg PointConfig, v app.Analog) error {
	return db.Add(AnalogOutput, index, cfg, v)
}

// AddOctetString adds an octet string (groups 110 and 111).
func (db *Database) AddOctetString(index uint32, cfg PointConfig, data []byte) error {
	return db.Add(OctetString, index, cfg, app.OctetString{Data: data})
}

// UpdateBinaryInput updates a binary input.
func (db *Database) UpdateBinaryInput(index uint32, v app.Binary) error {
	return db.Update(BinaryInput, index, v, EventOnChange)
}

// UpdateDoubleBitInput updates a double-bit binary input.
func (db *Database) UpdateDoubleBitInput(index uint32, v app.DoubleBitBinary) error {
	return db.Update(DoubleBitInput, index, v, EventOnChange)
}

// UpdateBinaryOutput updates a binary output status.
func (db *Database) UpdateBinaryOutput(index uint32, v app.Binary) error {
	return db.Update(BinaryOutput, index, v, EventOnChange)
}

// UpdateCounter updates a counter.
func (db *Database) UpdateCounter(index uint32, v app.Counter) error {
	return db.Update(Counter, index, v, EventOnChange)
}

// UpdateAnalogInput updates an analog input.
func (db *Database) UpdateAnalogInput(index uint32, v app.Analog) error {
	return db.Update(AnalogInput, index, v, EventOnChange)
}

// UpdateAnalogOutput updates an analog output status.
func (db *Database) UpdateAnalogOutput(index uint32, v app.Analog) error {
	return db.Update(AnalogOutput, index, v, EventOnChange)
}

// UpdateOctetString updates an octet string.
func (db *Database) UpdateOctetString(index uint32, data []byte) error {
	return db.Update(OctetString, index, app.OctetString{Data: data}, EventOnChange)
}
