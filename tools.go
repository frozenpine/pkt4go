package pkt4go

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

func NByte(buffer []byte, offset *int) uint8 {
	result := buffer[*offset]

	(*offset)++

	return result
}

func N2HShort(buffer []byte, offset *int) uint16 {
	result := binary.BigEndian.Uint16(buffer[*offset:])

	(*offset) += 2

	return result
}

func N2HLong(buffer []byte, offset *int) uint32 {
	result := binary.BigEndian.Uint32(buffer[*offset:])

	(*offset) += 4

	return result
}

func ReadBytes(dst []byte, buffer []byte, offset *int) error {
	if len(buffer) < len(dst) {
		return errors.New("insufficient data length")
	}

	*offset += copy(dst, buffer)

	return nil
}
