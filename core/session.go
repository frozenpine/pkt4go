package core

import (
	"bytes"
	"net"
	"strconv"
)

type Session struct {
	Proto   TransProto
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
}

func (s *Session) SrcAddr() net.Addr {
	switch s.Proto {
	case TCP:
		return &net.TCPAddr{IP: s.SrcIP, Port: s.SrcPort}
	case UDP:
		return &net.UDPAddr{IP: s.SrcIP, Port: s.SrcPort}
	default:
		return nil
	}
}

func (s *Session) DstAddr() net.Addr {
	switch s.Proto {
	case TCP:
		return &net.TCPAddr{IP: s.DstIP, Port: s.DstPort}
	case UDP:
		return &net.UDPAddr{IP: s.DstIP, Port: s.DstPort}
	default:
		return nil
	}
}

func (s *Session) String() string {
	buff := bytes.NewBufferString("[")
	buff.WriteString(s.Proto.String())
	buff.WriteString("] ")
	buff.WriteString(s.SrcIP.String())
	buff.WriteRune(':')
	buff.WriteString(strconv.Itoa(int(s.SrcPort)))
	buff.WriteString(" -> ")
	buff.WriteString(s.DstIP.String())
	buff.WriteRune(':')
	buff.WriteString(strconv.Itoa(int(s.DstPort)))

	return buff.String()
}
