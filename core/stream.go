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

func (cache *StreamCache) Free() int {
	return cache.cap - cache.offset
}

func (cache *StreamCache) Len() int {
	return cache.offset - cache.used
}

func (cache *StreamCache) Cap() int {
	return cache.cap
}

func (cache *StreamCache) append(data []byte) {
	size := len(data)

	if size <= 0 {
		return
	}

	if size > cache.Free() {
		len := cache.Len()
		total := size + len

		if total <= cache.cap && len <= cache.used {
			log.Printf(
				"Moving existing buffer[%d:%d] with cap[%d] for free space %d",
				cache.used, cache.offset, cache.cap, size)

			copy(cache.buffer, cache.Bytes())
			cache.used = 0
			cache.offset = len
		} else {
			var newCap int
			if size < cache.cap/2 {
				newCap = cache.cap + size*2
			} else {
				newCap = cache.cap + size
			}
			log.Printf(
				"No sufficent space[%d:%d:%d]"+
					" for data[%d], creating new[%d]",
				cache.used, cache.offset, cache.cap,
				size, newCap,
			)

			newBuffer := make([]byte, newCap)
			copy(newBuffer, cache.Bytes())
			cache.offset -= cache.used
			cache.used = 0
			cache.buffer = newBuffer
			cache.cap = newCap
		}
	}

	copy(cache.buffer[cache.offset:], data)
	cache.offset += size
}

// Rotate 滚动已使用数据
func (cache *StreamCache) Rotate(used int, data []byte) {
	if used > cache.offset-cache.used {
		log.Printf(
			"Rotate len[%d] exceeded, discarding exist buffer[%d:%d]",
			used, cache.used, cache.offset,
		)
		cache.used = 0
		cache.offset = 0
	} else if cache.used+used == cache.offset {
		log.Printf(
			"All exist buffer[%d:%d] rotated[%d]",
			cache.used, cache.offset, used,
		)
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
	if len(data) <= 0 {
		return cache.Bytes()
	}

	if cache.offset <= 0 || cache.used >= cache.offset {
		cache.offset = 0
		cache.used = 0
	}

	size := len(data)
	remain := cache.offset - cache.used
	cache.append(data)
	log.Printf("Stream buffer[%d] merged[%d] with remain[%d]",
		cache.Len(), size, remain)

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
