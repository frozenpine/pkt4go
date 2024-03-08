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

	rotate := 1
	cache.Rotate(rotate, nil)

	buff = cache.Merge(data)
	if slices.Compare(buff, append(data[rotate:], data...)) != 0 {
		t.Fatal("remain merge failed")
	}

	cache.Rotate(len(data)*3, data)

	if slices.Compare(cache.Bytes(), data) != 0 {
		t.Fatal("exceed rotate failed")
	}

	result := cache.Merge(make([]byte, 4096))
	if slices.Compare(result, append(data, make([]byte, 4096)...)) != 0 {
		t.Fatal("extend failed")
	}
}
