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
	used   int
	buffer []byte
}

func (cache *StreamCache) append(data []byte) {
	size := len(data)

	if size <= 0 {
		return
	}

	if cache.offset+size > cache.cap {
		cache.cap += size * 2
		newBuffer := make([]byte, cache.cap)
		copy(newBuffer, cache.buffer[cache.used:cache.offset])
		cache.offset -= cache.used
		pool.PutByteSlice(cache.buffer)
		cache.buffer = newBuffer
	}

	copy(cache.buffer[cache.offset:], data)
	cache.offset += size
}

// Rotate 滚动已使用数据
func (cache *StreamCache) Rotate(used int, data []byte) {
	if used > cache.offset-cache.used {
		cache.used = 0
		cache.offset = 0
	} else {
		cache.used += used
	}

	cache.append(data)
}

func (cache *StreamCache) Bytes() []byte {
	return cache.buffer[cache.used:cache.offset]
}

// Merge 合并数据至已有缓存
func (cache *StreamCache) Merge(data []byte) []byte {
	if cache.offset <= 0 {
		cache.offset = 0
		cache.used = 0
	}

	size := len(data)
	remain := cache.offset - cache.used
	cache.append(data)
	log.Printf("Stream buffer[%d] merged[%d] with remain[%d]",
		cache.offset, size, remain)

	return cache.Bytes()
}

func NewStreamCache() *StreamCache {
	return &StreamCache{
		cap:    pool.MaxBytesSize,
		buffer: make([]byte, pool.MaxBytesSize),
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
