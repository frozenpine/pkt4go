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
		SrcAddr:  src,
		SrcPort:  1000,
		DstAddr:  dst,
		DstPort:  2000,
	}

	hash := session.FastHash()

	t.Log(hash)
}
