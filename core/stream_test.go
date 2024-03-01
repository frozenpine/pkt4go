package core

import (
	"net"
	"slices"
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

func TestStreamCache(t *testing.T) {
	cache := NewStreamCache()

	data := []byte{1, 2, 3}

	buff := cache.Merge(data)
	if slices.Compare(buff, data) != 0 {
		t.Fatal("initial merge failed")
	}

	cache.Rotate(1, data[1:])

	buff = cache.Merge(data)
	if len(buff) != (len(data)-1)*2+len(data) {
		t.Fatal("remain merge failed")
	}

	cache.Rotate(len(data)*3, data)

	if slices.Compare(cache.Bytes(), data) != 0 {
		t.Fatal("exceed rotate failed")
	}
}
