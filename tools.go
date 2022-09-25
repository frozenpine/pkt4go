package pkt4go

import (
	"encoding/binary"
)

func nbyte(buffer []byte, offset *int) uint8 {
	result := buffer[*offset]

	(*offset)++

	return result
}

func ntohs(buffer []byte, offset *int) uint16 {
	result := binary.BigEndian.Uint16(buffer[*offset:])

	(*offset) += 2

	return result
}

func ntohl(buffer []byte, offset *int) uint32 {
	result := binary.BigEndian.Uint32(buffer[*offset:])

	(*offset) += 4

	return result
}
