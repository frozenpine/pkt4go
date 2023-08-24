package core_test

import (
	"net"
	"testing"

	"github.com/frozenpine/pkt4go/core"
)

func TestSession(t *testing.T) {
	src, dst := core.IPv4Addr{}, core.IPv4Addr{}
	copy(src[:], net.ParseIP("192.168.1.1").To4())
	copy(dst[:], net.ParseIP("192.168.1.2").To4())

	session := core.Session{
		Proto:   core.TCP,
		SrcIP:   net.IP(src[:]),
		SrcPort: 1000,
		DstIP:   net.IP(dst[:]),
		DstPort: 2000,
	}

	t.Log(session)
}

func TestTypePrint(t *testing.T) {
	ip := core.ProtoIP

	tcp := core.TCP

	t.Logf("%#04x %#02x", uint16(ip), byte(tcp))
}
