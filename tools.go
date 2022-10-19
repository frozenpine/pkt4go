package pkt4go

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/pkg/errors"
)

func NByte(buffer []byte, offset *int) uint8 {
	result := buffer[*offset]

	if offset != nil {
		(*offset)++
	}

	return result
}

func N2HShort(buffer []byte, offset *int) uint16 {
	result := binary.BigEndian.Uint16(buffer[*offset:])

	(*offset) += 2

	return result
}

func N2HLong(buffer []byte, offset *int) uint32 {
	result := binary.BigEndian.Uint32(buffer[*offset:])

	if offset != nil {
		(*offset) += 4
	}

	return result
}

func ReadBytes(dst []byte, buffer []byte, offset *int) error {
	if len(buffer) < len(dst) {
		return errors.New("insufficient data length")
	}

	if offset != nil {
		*offset += copy(dst, buffer)
	}

	return nil
}

func N2HDouble(buffer []byte, offset *int) float64 {
	bits := binary.BigEndian.Uint64(buffer)
	result := math.Float64frombits(bits)

	if offset != nil {
		*offset += 8
	}

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
