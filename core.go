package pkt4go

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

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
)

var (
	ErrInsufficentData     = origin_errors.New("insufficent data length")
	ErrUnpackOffset        = origin_errors.New("invalid unpack offset")
	ErrUnInitializedParent = origin_errors.New("un-initialized parent layer")
)

// MACAddr ethernet mac address
type MACAddr [6]byte

func (addr MACAddr) String() string {
	return fmt.Sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2],
		addr[3], addr[4], addr[5],
	)
}

type EtherType uint16

const (
	ProtoIP EtherType = 0x0800 // ip
)

// EtherHeader ethernet header
type EtherHeader struct {
	// Destination host address
	DstHost MACAddr
	// Source host address
	SrcHost MACAddr
	// IP? ARP? RARP? etc
	Type EtherType
}

func (hdr *EtherFrame) Unpack(buff []byte) error {
	buffLen := len(buff)
	if buffLen < EtherHeaderSize {
		return errors.WithStack(ErrInsufficentData)
	}

	offset := 0

	offset += copy(hdr.DstHost[:], buff[offset:])

	offset += copy(hdr.SrcHost[:], buff[offset:])

	hdr.Type = EtherType(ntohs(buff, &offset))

	if offset != EtherHeaderSize {
		panic(errors.Wrap(
			ErrUnpackOffset,
			fmt.Sprintf(
				"eh[%d] offset invalid: %d",
				EtherHeaderSize, offset,
			)))
	}

	return nil
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

func (hdr *IPv4Header) Unpack(buff []byte) error {
	buffSize := len(buff)
	if buffSize < IPv4HeaderBaseSize {
		return errors.WithStack(ErrInsufficentData)
	}

	offset := 0

	hdr.VerIHL = nbyte(buff, &offset)

	hdr.TOS = nbyte(buff, &offset)

	hdr.TotalLength = ntohs(buff, &offset)

	hdr.Identification = ntohs(buff, &offset)

	hdr.Flags = ntohs(buff, &offset)

	hdr.TTL = nbyte(buff, &offset)

	hdr.Protocol = TransProto(nbyte(buff, &offset))

	hdr.CRC = ntohs(buff, &offset)

	offset += copy(hdr.SrcAddr[:], buff[offset:])
	offset += copy(hdr.DstAddr[:], buff[offset:])

	if offset != IPv4HeaderBaseSize {
		panic(errors.Wrap(
			ErrUnpackOffset,
			fmt.Sprintf(
				"ih[%d] offset invalid: %d",
				IPv4HeaderBaseSize, offset,
			)))
	}

	return nil
}

func (hdr *IPv4Header) PayloadOffset() int {
	return int(hdr.VerIHL&0xf) * 4
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
		return errors.WithStack(ErrInsufficentData)
	}

	offset := 0

	hdr.SrcPort = ntohs(buff, &offset)

	hdr.DstPort = ntohs(buff, &offset)

	hdr.Seq = TCPSeq(ntohl(buff, &offset))

	hdr.Ack = TCPSeq(ntohl(buff, &offset))

	hdr.Offset = TCPOffset(nbyte(buff, &offset))

	hdr.Flags = TCPFlags(nbyte(buff, &offset))

	hdr.Window = ntohs(buff, &offset)

	hdr.Checksum = ntohs(buff, &offset)

	if offset != TCPHeaderBaseSize {
		panic(errors.Wrap(
			ErrUnpackOffset,
			fmt.Sprintf(
				"th[%d] offset invalid: %d",
				TCPHeaderBaseSize, offset,
			)))
	}

	return nil
}

func (hdr *TCPHeader) PayloadOffset() int {
	return int(hdr.Offset>>4) * 4
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

func (hdr *UDPHeader) Unpack(buff []byte) error {
	buffLen := len(buff)
	if buffLen < UDPHeaderSize {
		return errors.WithStack(ErrInsufficentData)
	}

	offset := 0

	hdr.SrcPort = ntohs(buff, &offset)

	hdr.DstPort = ntohs(buff, &offset)

	hdr.Len = ntohs(buff, &offset)

	hdr.CRC = ntohs(buff, &offset)

	if offset != UDPHeaderSize {
		panic(errors.Wrap(
			ErrUnpackOffset,
			fmt.Sprintf(
				"uh[%d] offset invalid: %d",
				UDPHeaderSize, offset,
			)))
	}

	return nil
}

func (hdr *UDPHeader) PayloadOffset() int {
	return UDPHeaderSize
}

type PktData interface {
	Unpack([]byte) error
	Release()
	GetParent() PktData
	GetPayload() []byte
	GetTimestamp() time.Time
}

type EtherFrame struct {
	EtherHeader
	Buffer    []byte
	Timestamp time.Time
}

func (frm *EtherFrame) Release() {
	etherFrmPool.Put(frm)
	// payloadPool.Put(frm.Buffer)
}

func (frm *EtherFrame) GetParent() PktData {
	return nil
}

func (frm *EtherFrame) GetPayload() []byte {
	if len(frm.Buffer) < EtherHeaderSize {
		panic(errors.WithStack(ErrInsufficentData))
	}

	return frm.Buffer[EtherHeaderSize:]
}

func (frm *EtherFrame) GetTimestamp() time.Time {
	return frm.Timestamp
}

type IPv4Packet struct {
	IPv4Header
	parent *EtherFrame
}

func (pkt *IPv4Packet) Release() {
	ipv4PktPool.Put(pkt)

	if pkt.parent != nil {
		pkt.parent.Release()
	}
}

func (pkt *IPv4Packet) GetParent() PktData {
	return pkt.parent
}

func (pkt *IPv4Packet) GetPayload() []byte {
	if pkt.parent == nil {
		panic(errors.WithStack(ErrUnInitializedParent))
	}

	return pkt.parent.GetPayload()[pkt.PayloadOffset():]
}

func (pkt *IPv4Packet) GetTimestamp() time.Time {
	return pkt.parent.GetTimestamp()
}

type TCPSegment struct {
	TCPHeader
	parent *IPv4Packet
}

func (seg *TCPSegment) Release() {
	tcpSegPool.Put(seg)
	seg.parent.Release()
}

func (seg *TCPSegment) GetParent() PktData {
	return seg.parent
}

func (seg *TCPSegment) GetPayload() []byte {
	return seg.parent.GetPayload()[seg.PayloadOffset():]
}

func (seg *TCPSegment) GetTimestamp() time.Time {
	return seg.parent.GetTimestamp()
}

type UDPSegment struct {
	UDPHeader
	parent *IPv4Packet
}

func (seg *UDPSegment) Release() {
	udpSegPool.Put(seg)
	seg.parent.Release()
}

func (seg *UDPSegment) GetParent() PktData {
	return seg.parent
}

func (seg *UDPSegment) GetPayload() []byte {
	return seg.parent.GetPayload()[seg.PayloadOffset():]
}

func (seg *UDPSegment) GetTimestamp() time.Time {
	return seg.parent.GetTimestamp()
}

var (
	mtu          = 1500
	etherFrmPool = sync.Pool{New: func() any { return &EtherFrame{} }}
	ipv4PktPool  = sync.Pool{New: func() any { return &IPv4Packet{} }}
	tcpSegPool   = sync.Pool{New: func() any { return &TCPSegment{} }}
	udpSegPool   = sync.Pool{New: func() any { return &UDPSegment{} }}
	// payloadPool  = sync.Pool{New: func() any { return make([]byte, mtu) }}
)

func SetMTU(v int) {
	mtu = v
}

func GetMTU() int {
	return mtu
}

func CreateEtherFrame() *EtherFrame {
	return etherFrmPool.Get().(*EtherFrame)
}

func CreateIPv4Packet(frm *EtherFrame) *IPv4Packet {
	pkt := ipv4PktPool.Get().(*IPv4Packet)
	pkt.parent = frm
	return pkt
}

func CreateTCPSegment(pkt *IPv4Packet) *TCPSegment {
	seg := tcpSegPool.Get().(*TCPSegment)
	seg.parent = pkt
	return seg
}

func CreateUDPSegment(pkt *IPv4Packet) *UDPSegment {
	seg := udpSegPool.Get().(*UDPSegment)
	seg.parent = pkt
	return seg
}
