package pkt4go

import (
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	origin_errors "errors"
)

// DataHandler transport payload handler
type DataHandler func(src, dst net.Addr, ts time.Time, data []byte) (int, error)

type DataMode uint

const (
	TCPFullData DataMode = iota
	TCPRawData
)

const defaultDataMode = TCPFullData

var (
	TCPDataMode = defaultDataMode
)

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

//go:generate stringer -type EtherType -linecomment
const (
	ProtoIP   EtherType = 0x0800 // ip
	ProtoARP  EtherType = 0x0806 // arp
	ProtoRARP EtherType = 0x0835 // rarp
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

	hdr.Type = EtherType(N2HShort(buff, &offset))

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

	hdr.VerIHL = NByte(buff, &offset)

	hdr.TOS = NByte(buff, &offset)

	hdr.TotalLength = N2HShort(buff, &offset)

	hdr.Identification = N2HShort(buff, &offset)

	hdr.Flags = N2HShort(buff, &offset)

	hdr.TTL = NByte(buff, &offset)

	hdr.Protocol = TransProto(NByte(buff, &offset))

	hdr.CRC = N2HShort(buff, &offset)

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

	hdr.SrcPort = N2HShort(buff, &offset)

	hdr.DstPort = N2HShort(buff, &offset)

	hdr.Seq = TCPSeq(N2HLong(buff, &offset))

	hdr.Ack = TCPSeq(N2HLong(buff, &offset))

	hdr.Offset = TCPOffset(NByte(buff, &offset))

	hdr.Flags = TCPFlags(NByte(buff, &offset))

	hdr.Window = N2HShort(buff, &offset)

	hdr.Checksum = N2HShort(buff, &offset)

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

	hdr.SrcPort = N2HShort(buff, &offset)

	hdr.DstPort = N2HShort(buff, &offset)

	hdr.Len = N2HShort(buff, &offset)

	hdr.CRC = N2HShort(buff, &offset)

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
	PreLayer() PktData
	NextLayer() PktData
	GetPayload() []byte
	GetTimestamp() time.Time
}

type EtherFrame struct {
	EtherHeader
	Buffer    []byte
	Timestamp time.Time
	nextLayer *IPv4Packet
	release   func()
}

func (frm *EtherFrame) Release() {
	frm.nextLayer = nil

	etherFrmPool.Put(frm)
	payloadPool.Put(frm.Buffer)

	if frm.release != nil {
		frm.release()
	}
}

func (frm *EtherFrame) DelegateRelease(fn func()) {
	frm.release = fn
}

func (frm *EtherFrame) PreLayer() PktData {
	return nil
}

func (frm *EtherFrame) NextLayer() PktData {
	return frm.nextLayer
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
	preLayer  *EtherFrame
	nextLayer PktData
}

func (pkt *IPv4Packet) Release() {
	pkt.nextLayer = nil

	if pkt.preLayer != nil {
		pkt.preLayer.Release()
		pkt.preLayer = nil
	}

	ipv4PktPool.Put(pkt)
}

func (pkt *IPv4Packet) PreLayer() PktData {
	return pkt.preLayer
}

func (pkt *IPv4Packet) NextLayer() PktData {
	return pkt.nextLayer
}

func (pkt *IPv4Packet) GetPayload() []byte {
	if pkt.preLayer == nil {
		panic(errors.WithStack(ErrUnInitializedParent))
	}

	return pkt.preLayer.GetPayload()[pkt.PayloadOffset():]
}

func (pkt *IPv4Packet) GetTimestamp() time.Time {
	return pkt.preLayer.GetTimestamp()
}

type Session struct {
	Protocol TransProto
	SrcAddr  IPv4Addr
	SrcPort  uint16
	DstAddr  IPv4Addr
	DstPort  uint16
}

const (
	fnvBasis = 14695981039346656037
	fnvPrime = 1099511628211
)

func (s *Session) FastHash() (h uint64) {
	size := int(unsafe.Sizeof(*s))

	rawBytes := *(*[]byte)(unsafe.Pointer(
		&reflect.SliceHeader{
			Data: uintptr(unsafe.Pointer(s)),
			Len:  size,
			Cap:  size,
		},
	))

	h = fnvBasis

	for i := 0; i < len(rawBytes); i++ {
		h ^= uint64(rawBytes[i])
		h *= fnvPrime
	}

	return
}

type TCPSegment struct {
	TCPHeader
	preLayer  *IPv4Packet
	nextLayer PktData
}

func (seg *TCPSegment) Release() {
	seg.nextLayer = nil

	if seg.preLayer != nil {
		seg.preLayer.Release()
		seg.preLayer = nil
	}

	tcpSegPool.Put(seg)
}

func (seg *TCPSegment) PreLayer() PktData {
	return seg.preLayer
}

func (seg *TCPSegment) NextLayer() PktData {
	return seg.nextLayer
}

func (seg *TCPSegment) GetPayload() []byte {
	return seg.preLayer.GetPayload()[seg.PayloadOffset():]
}

func (seg *TCPSegment) GetTimestamp() time.Time {
	return seg.preLayer.GetTimestamp()
}

func (seg *TCPSegment) Flow() *Session {
	ih := seg.preLayer

	return &Session{
		Protocol: TCP,
		SrcAddr:  ih.SrcAddr,
		SrcPort:  seg.SrcPort,
		DstAddr:  ih.DstAddr,
		DstPort:  seg.DstPort,
	}
}

type UDPSegment struct {
	UDPHeader
	preLayer  *IPv4Packet
	nextLayer PktData
}

func (seg *UDPSegment) Release() {
	seg.nextLayer = nil

	if seg.preLayer != nil {
		seg.preLayer.Release()
		seg.preLayer = nil
	}

	udpSegPool.Put(seg)
}

func (seg *UDPSegment) PreLayer() PktData {
	return seg.preLayer
}

func (seg *UDPSegment) NextLayer() PktData {
	return seg.nextLayer
}

func (seg *UDPSegment) GetPayload() []byte {
	return seg.preLayer.GetPayload()[seg.PayloadOffset():]
}

func (seg *UDPSegment) GetTimestamp() time.Time {
	return seg.preLayer.GetTimestamp()
}

func (seg *UDPSegment) Flow() *Session {
	ih := seg.preLayer

	return &Session{
		Protocol: UDP,
		SrcAddr:  ih.SrcAddr,
		SrcPort:  seg.SrcPort,
		DstAddr:  ih.DstAddr,
		DstPort:  seg.DstPort,
	}
}

var (
	mtu          = 1500
	etherFrmPool = sync.Pool{New: func() any { return &EtherFrame{Buffer: payloadPool.Get().([]byte)} }}
	ipv4PktPool  = sync.Pool{New: func() any { return &IPv4Packet{} }}
	tcpSegPool   = sync.Pool{New: func() any { return &TCPSegment{} }}
	udpSegPool   = sync.Pool{New: func() any { return &UDPSegment{} }}
	payloadPool  = sync.Pool{New: func() any { return make([]byte, mtu) }}
)

func SetMTU(v int) {
	mtu = v
}

func GetMTU() int {
	return mtu
}

func CreateEmptyEtherFrame() *EtherFrame {
	return etherFrmPool.Get().(*EtherFrame)
}

func CreateEtherFrame(buffer []byte, ts time.Time) *EtherFrame {
	frm := CreateEmptyEtherFrame()
	frm.Timestamp = ts
	frm.Buffer = buffer

	return frm
}

func CreateIPv4Packet(frm *EtherFrame) *IPv4Packet {
	pkt := ipv4PktPool.Get().(*IPv4Packet)
	pkt.preLayer = frm
	frm.nextLayer = pkt
	return pkt
}

func CreateTCPSegment(pkt *IPv4Packet) *TCPSegment {
	seg := tcpSegPool.Get().(*TCPSegment)
	seg.preLayer = pkt
	return seg
}

func CreateUDPSegment(pkt *IPv4Packet) *UDPSegment {
	seg := udpSegPool.Get().(*UDPSegment)
	seg.preLayer = pkt
	return seg
}
