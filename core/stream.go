package core

import (
	"log"

	"github.com/frozenpine/pool"
)

type StreamCache struct {
	cap    int
	offset int
	buffer []byte
}

func (cache *StreamCache) Append(buf []byte) int {
	size := len(buf)

	if size <= 0 {
		return 0
	}

	if cache.offset+size > cache.cap {
		cache.cap += size * 2
		newBuffer := make([]byte, cache.cap)
		copy(newBuffer, cache.buffer[:cache.offset])
		pool.PutByteSlice(cache.buffer)
		cache.buffer = newBuffer
	}

	copy(cache.buffer[cache.offset:], buf)

	cache.offset += size

	return cache.offset
}

func (cache *StreamCache) Merge(data []byte) []byte {
	if cache.offset <= 0 {
		return data
	}

	size := len(data)
	remain := cache.offset
	total := remain + size
	cache.Append(data)
	log.Printf("Stream buffer[%d] merged[%d] with remain[%d]", total, size, remain)
	cache.offset = 0
	return cache.buffer[:total]
}

func NewStreamCache() *StreamCache {
	return &StreamCache{
		cap:    pool.MaxBytesSize,
		buffer: pool.GetByteSlice(),
	}
}

var defaultStreamCaches = map[string]*StreamCache{}

func GetStreamCache(session *Session) *StreamCache {
	s := session.String()

	cache, exist := defaultStreamCaches[s]

	if !exist {
		cache = NewStreamCache()
		defaultStreamCaches[s] = cache
	}

	return cache
}
