package core

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/frozenpine/pkt4go/utils"
)

type Buffer struct {
	origin *bytes.Buffer
	data   []byte
}

func NewBuffer(data []byte) *Buffer {
	buffer := Buffer{
		data:   data,
		origin: bytes.NewBuffer(data),
	}

	return &buffer
}

func (buf *Buffer) ReadByte() (byte, error) {
	return buf.origin.ReadByte()
}

func (buf *Buffer) Bytes() []byte {
	return buf.origin.Bytes()
}

func (buf *Buffer) ReadBytes(delim byte) ([]byte, error) {
	return buf.origin.ReadBytes(delim)
}

func (buf *Buffer) ReadUint8() uint8 {
	if v, err := buf.origin.ReadByte(); err != nil {
		panic(err)
	} else {
		return v
	}
}

func (buf *Buffer) ReadNShort() uint16 {
	v := binary.BigEndian.Uint16(buf.origin.Next(2))

	return v
}

func (buf *Buffer) ReadHShort() uint16 {
	v := binary.LittleEndian.Uint16(buf.origin.Next(2))

	return v
}

func (buf *Buffer) ReadNLong() uint32 {
	v := binary.BigEndian.Uint32(buf.origin.Next(4))

	return v
}

func (buf *Buffer) ReadHLong() uint32 {
	v := binary.LittleEndian.Uint32(buf.origin.Next(4))

	return v
}

func (buf *Buffer) ReadNLongLong() uint64 {
	v := binary.BigEndian.Uint64(buf.origin.Next(8))

	return v
}

func (buf *Buffer) ReadHLongLong() uint64 {
	v := binary.LittleEndian.Uint64(buf.origin.Next(8))

	return v
}

func (buf *Buffer) ReadNDouble() float64 {
	bits := binary.BigEndian.Uint64(buf.origin.Next(8))
	result := math.Float64frombits(bits)

	return result
}

func (buf *Buffer) ReadHDouble() float64 {
	bits := binary.LittleEndian.Uint64(buf.origin.Next(8))
	result := math.Float64frombits(bits)

	return result
}

func (buf *Buffer) ReadNSingle() float32 {
	bits := binary.BigEndian.Uint32(buf.origin.Next(4))
	result := math.Float32frombits(bits)

	return result
}

func (buf *Buffer) ReadHSingle() float32 {
	bits := binary.LittleEndian.Uint32(buf.origin.Next(4))
	result := math.Float32frombits(bits)

	return result
}

func (buf *Buffer) Read(p []byte) (n int, err error) {
	n, err = buf.origin.Read(p)

	return
}

func (buf *Buffer) ReadCStr(n int) string {
	p := make([]byte, n)
	var err error

	_, err = buf.Read(p)

	if err != nil && err != io.EOF {
		panic(err)
	}

	return utils.CStr2GoStr(p)
}

func (buf *Buffer) Offset() int {
	return len(buf.data) - buf.origin.Len()
}

func (buf *Buffer) Cap() int {
	return buf.origin.Cap()
}

func (buf *Buffer) Len() int {
	return buf.origin.Len()
}

func (buf *Buffer) Next(n int) []byte {
	if n <= 0 {
		return nil
	}

	v := buf.origin.Next(n)

	return v
}

func (buf *Buffer) Reset() {
	buf.origin = bytes.NewBuffer(buf.data)
}

func (buf *Buffer) Unread(n int) {
	offset := buf.Offset()

	buf.Reset()

	if n >= offset {
		return
	}

	buf.Next(offset - n)
}
