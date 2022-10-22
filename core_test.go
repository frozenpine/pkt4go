package pkt4go_test

import (
	"net"
	"testing"

	"github.com/frozenpine/pkt4go"
)

func TestSession(t *testing.T) {
	src, dst := pkt4go.IPv4Addr{}, pkt4go.IPv4Addr{}
	copy(src[:], net.ParseIP("192.168.1.1").To4())
	copy(dst[:], net.ParseIP("192.168.1.2").To4())

	session := pkt4go.Session{
		Protocol: pkt4go.TCP,
		SrcAddr:  net.IP(src[:]),
		SrcPort:  1000,
		DstAddr:  net.IP(dst[:]),
		DstPort:  2000,
	}

	t.Log(session)
}

func TestTypePrint(t *testing.T) {
	ip := pkt4go.ProtoIP

	tcp := pkt4go.TCP

	t.Logf("%#04x %#02x", uint16(ip), byte(tcp))
}
