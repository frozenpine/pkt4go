package pkt4go

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/pkg/errors"
)

func NByte(buffer []byte, offset *int) uint8 {
	idx := 0

	if offset != nil {
		idx = *offset
		(*offset)++
	}

	result := buffer[idx]

	return result
}

func N2HShort(buffer []byte, offset *int) uint16 {
	idx := 0

	if offset != nil {
		idx = *offset
		(*offset) += 2
	}

	result := binary.BigEndian.Uint16(buffer[idx:])

	return result
}

func N2HLong(buffer []byte, offset *int) uint32 {
	idx := 0

	if offset != nil {
		idx = *offset
		(*offset) += 4
	}

	result := binary.BigEndian.Uint32(buffer[idx:])

	return result
}

func ReadBytes(dst []byte, buffer []byte, offset *int) error {
	idx := 0

	if offset != nil {
		idx = *offset
	}
	buffer = buffer[idx:]

	if len(buffer) < len(dst) {
		return errors.New("insufficient data length")
	}

	if copyLen := copy(dst, buffer); offset != nil {
		*offset += copyLen
	}

	return nil
}

func N2HDouble(buffer []byte, offset *int) float64 {
	idx := 0

	if offset != nil {
		idx = *offset
		*offset += 8
	}

	bits := binary.BigEndian.Uint64(buffer[idx:])
	result := math.Float64frombits(bits)

	return result
}

func findCStrTerm(in []byte) (idx int) {
	idx = bytes.IndexByte(in, 0x0)

	if idx < 0 {
		idx = 0
	}

	return
}

func CStr2GoStr(in []byte) string {
	return string(in[:findCStrTerm(in)])
}
