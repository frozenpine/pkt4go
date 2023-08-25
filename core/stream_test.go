package core

import (
	"net"
	"testing"
)

func TestSessionKey(t *testing.T) {
	s := Session{
		Proto:   UDP,
		SrcIP:   net.ParseIP("192.168.1.1"),
		SrcPort: 1234,
		DstIP:   net.ParseIP("192.168.1.2"),
		DstPort: 4321,
	}

	key := makeSessionKey(&s)

	t.Log(len(key), key)
}
