package core

import (
	"log"
	"strconv"

	"github.com/frozenpine/pool"
	"github.com/valyala/bytebufferpool"
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

var (
	defaultStreamCaches = map[string]*StreamCache{}
)

func makeSessionKey(session *Session) string {
	buff := bytebufferpool.Get()
	defer bytebufferpool.Put(buff)

	buff.WriteString(session.Proto.String())
	buff.WriteString(session.SrcIP.String())
	buff.WriteString(strconv.Itoa(session.SrcPort))
	buff.WriteString(session.DstIP.String())
	buff.WriteString(strconv.Itoa(session.DstPort))

	return buff.String()
}

func GetStreamCache(session *Session) *StreamCache {
	key := makeSessionKey(session)

	cache, exist := defaultStreamCaches[key]
	if !exist {
		cache = NewStreamCache()
		defaultStreamCaches[key] = cache
	}

	return cache
}
