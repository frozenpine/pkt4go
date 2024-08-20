package core

import (
	"net"
	"strconv"

	"github.com/valyala/bytebufferpool"
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
	buff := bytebufferpool.Get()
	defer bytebufferpool.Put(buff)

	buff.WriteByte('[')
	buff.WriteString(s.Proto.String())
	buff.WriteString("] ")
	buff.WriteString(s.SrcIP.String())
	buff.WriteByte(':')
	buff.WriteString(strconv.Itoa(s.SrcPort))
	buff.WriteString(" -> ")
	buff.WriteString(s.DstIP.String())
	buff.WriteByte(':')
	buff.WriteString(strconv.Itoa(s.DstPort))

	return buff.String()
}
