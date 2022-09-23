package exanic

import "fmt"

// MACAddr mac address
type MACAddr [6]byte

// IPAddr ip address
type IPAddr struct {
	Sec1 uint8
	Sec2 uint8
	Sec3 uint8
	Sec4 uint8
}

func (addr *IPAddr) String() string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		addr.Sec1, addr.Sec2,
		addr.Sec3, addr.Sec4,
	)
}

// EtherHeader ethernet frame header
type EtherHeader struct {
	// Destination host address
	DstMAC MACAddr
	// Source host address
	SrcMAC MACAddr
	// IP? ARP? RARP? etc
	EtherType uint16
}

// IPHeader ipv4 header
type IPHeader struct {
	// Version (4 bits) + Internet header length (4 bits)
	VerIHL uint8
	// Type of service
	TOS uint8
	// Total length
	TotalLen uint16
	// Identification
	Identification uint16
	// Flags (3 bits) + Fragment offset (13 bits)
	FlagsFO uint16
	// Time to live
	TTL uint8
	// Protocol
	Protocol uint8
	// Header checksum
	CRC uint16
	// Source address
	SrcAddr IPAddr
	// Destination address
	DstAddr IPAddr
	// Option + Padding
	OpPad uint32
}
