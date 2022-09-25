package pkt4go

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/pkg/errors"

	origin_errors "errors"
)

// DataHandler transport payload handler
type DataHandler func(src, dst net.Addr, data []byte) (int, error)

var (
	EtherHeaderSize    = binary.Size(EtherHeader{})
	IPv4HeaderBaseSize = binary.Size(IPv4Header{})
	TCPHeaderBaseSize  = binary.Size(TCPHeader{})
	UDPHeaderSize      = binary.Size(UDPHeader{})

	ErrInsufficentData = origin_errors.New("insufficent data length")
)

// MACAddr ethernet mac address
type MACAddr [6]byte

func (addr MACAddr) String() string {
	return fmt.Sprintf(
		"%x:%x:%x:%x:%x:%x",
		addr[0], addr[1], addr[2],
		addr[3], addr[4], addr[5],
	)
}

type EtherType uint16

// EtherHeader ethernet header
type EtherHeader struct {
	// Destination host address
	DstHost MACAddr
	// Source host address
	SrcHost MACAddr
	// IP? ARP? RARP? etc
	Type EtherType
}

// IPv4Addr ip v4 address
type IPv4Addr [4]byte

func (addr IPv4Addr) String() string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		addr[0], addr[1], addr[2], addr[3],
	)
}

// TransProto transport protocol
type TransProto byte

//go:generate stringer -type TransProto -linecomment
const (
	TCP TransProto = 0x06 // tcp
	UDP TransProto = 0x11 // udp
)

// IPv4Header ip v4 header
type IPv4Header struct {
	// Version (4 bits) + Internet header length (4 bits)
	VerIHL uint8
	// Type of service
	TOS uint8
	// Total length
	TotalLength uint16
	// Identification
	Identification uint16
	// Flags (3 bits) + Fragment offset (13 bits)
	Flags uint16
	// Time to live
	TTL uint8
	// Protocol
	Protocol TransProto
	// Header checksum
	CRC uint16
	// Source address
	SrcAddr IPv4Addr
	// Destination address
	DstAddr IPv4Addr
}

func (hdr *IPv4Header) PayloadOffset() int {
	return int(hdr.VerIHL&0xf) * 4
}

func (hdr *IPv4Header) Unpack(buff []byte) error {
	buffSize := len(buff)
	if buffSize < IPv4HeaderBaseSize {
		return errors.Cause(ErrInsufficentData)
	}

	offset := 0

	hdr.VerIHL = buff[offset]
	offset++

	hdr.TOS = buff[offset]
	offset++

	hdr.TotalLength = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	hdr.Identification = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	hdr.Flags = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	hdr.TTL = buff[offset]
	offset++

	hdr.Protocol = TransProto(buff[offset])
	offset++

	hdr.CRC = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	offset += copy(hdr.SrcAddr[:], buff[offset:])
	offset += copy(hdr.DstAddr[:], buff[offset:])

	return nil
}

// TCPSeq tcp sequence
type TCPSeq uint32

// TCPOffset tcp header offset & data offset
type TCPOffset byte

// TCPFlags tcp flags
type TCPFlags byte

//go:generate stringer -type TCPFlags -linecomment
const (
	FIN TCPFlags = 1 << iota // finish
	SYN                      // sync
	RST                      // reset
	PUS                      // push
	ACK                      // acknowlege
	URG                      // urgent
	ECE                      // ece
	CWR                      // cwr
)

func (flag TCPFlags) HasFlag(f TCPFlags) bool {
	return flag&f == f
}

// TCPHeader tcp header
type TCPHeader struct {
	// source port
	SrcPort uint16
	// destination port
	DstPort uint16
	// sequence number
	Seq TCPSeq
	// acknowledgement number
	Ack TCPSeq
	// data offset, rsvd
	Offset TCPOffset
	// flags
	Flags TCPFlags
	// window size
	Window uint16
	// checksum
	Checksum uint16
}

func (hdr *TCPHeader) Unpack(buff []byte) error {
	buffLen := len(buff)

	if buffLen < TCPHeaderBaseSize {
		return errors.Cause(ErrInsufficentData)
	}

	offset := 0

	hdr.SrcPort = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	hdr.DstPort = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	hdr.Seq = TCPSeq(binary.BigEndian.Uint32(buff[offset:]))
	offset += 4

	hdr.Ack = TCPSeq(binary.BigEndian.Uint32(buff[offset:]))
	offset += 4

	hdr.Offset = TCPOffset(buff[offset])
	offset++

	hdr.Flags = TCPFlags(buff[offset])
	offset++

	hdr.Window = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	hdr.Checksum = binary.BigEndian.Uint16(buff[offset:])
	offset += 2

	return nil
}

// UDPHeader udp header
type UDPHeader struct {
	// source port
	SrcPort uint16
	// destination port
	DstPort uint16
	// Datagram length
	Len uint16
	// Checksum
	CRC uint16
}
