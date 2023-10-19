package core_test

import (
	"testing"

	"github.com/frozenpine/pkt4go/core"
)

func TestOffset(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	buffer := core.NewBuffer(data)

	offset := 0

	t.Log(buffer.ReadUint8())
	if offset = buffer.Offset(); offset != 1 {
		t.Fatal("Read byte failed.")
	}

	t.Log(buffer.ReadHShort())
	if offset = buffer.Offset(); offset != 3 {
		t.Fatal("Read short failed")
	}

	t.Log(buffer.ReadNLong())
	if offset = buffer.Offset(); offset != 7 {
		t.Fatal("Read long failed")
	}

	buffer.Unread(5)
	offset = buffer.Offset()
	cap := buffer.Cap()
	len := buffer.Len()
	if offset != 2 || cap != 8 || len != 6 {
		t.Fatal("Unread failed")
	}
}
