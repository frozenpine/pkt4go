package core

import "github.com/frozenpine/pool"

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
		cache.buffer = newBuffer
	}

	copy(cache.buffer[cache.offset:], buf)

	cache.offset += size

	return cache.offset
}

func (cache *StreamCache) Merge(buf []byte) []byte {
	if cache.offset <= 0 {
		return buf
	}

	cache.Append(buf)
	cache.offset = 0
	return cache.buffer
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
