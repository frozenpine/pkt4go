package cache

import (
	"sync"
)

func AlignUp(x int) int {
	return (x + 1) &^ 1
}

const MaxBytesSize = 4096

type BytesPool struct {
	size int
	pool sync.Pool
}

func NewBytesPool(size int) *BytesPool {
	if size <= 0 {
		size = MaxBytesSize
	} else {
		size = AlignUp(size)

		if size > MaxBytesSize {
			size = MaxBytesSize
		}
	}

	return &BytesPool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				return make([]byte, size)
			},
		},
	}
}

func (pool *BytesPool) GetSlice() []byte {
	bytes := pool.pool.Get().([]byte)
	for idx := range bytes {
		bytes[idx] = 0
	}

	return bytes
}

func (pool *BytesPool) GetBuffer() *Buffer {
	return NewBuffer(pool.GetSlice())
}

func (pool *BytesPool) PutSlice(data []byte) {
	if cap(data) < pool.size {
		return
	}

	pool.pool.Put(data[:pool.size])
}

func (pool *BytesPool) PutBuffer(buff *Buffer) {
	if cap(buff.data) < pool.size {
		return
	}

	pool.pool.Put(buff.data[:pool.size])
}
