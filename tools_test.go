package pkt4go

import "testing"

func TestOffset(t *testing.T) {
	offset := 0

	buffer := []byte{0, 1, 2, 3, 4, 5, 6}

	NByte(buffer, &offset)

	if offset != 1 {
		t.Fatal("nbyte error")
	}

	N2HShort(buffer, &offset)

	if offset != 3 {
		t.Fatal("ntoh error")
	}

	N2HLong(buffer, &offset)

	if offset != 7 {
		t.Fatal("ntohl error")
	}
}
