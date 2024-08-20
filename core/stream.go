package core

import (
	"log/slog"

	"github.com/frozenpine/pool"
)

type StreamCache struct {
	cap    int
	offset int
	used   int
	buffer []byte
}

// Free 返回底层缓冲区的可用
func (cache *StreamCache) Free() int {
	return cache.cap - cache.offset
}

// Len 剩余未使用数据长度
func (cache *StreamCache) Len() int {
	return cache.offset - cache.used
}

// Cap 返回底层缓冲区的cap
func (cache *StreamCache) Cap() int {
	return cache.cap
}

func (cache *StreamCache) append(data []byte) {
	size := len(data)

	if size <= 0 {
		return
	}

	if size > cache.Free() {
		if len := cache.Len(); size+len <= cache.cap && len <= cache.used {
			slog.Debug(
				"moving buffer forward for extra data:",
				slog.Group(
					"before",
					slog.Int("used", cache.used),
					slog.Int("offset", cache.offset),
					slog.Int("cap", cache.cap),
				),
				slog.Int("data", size),
				slog.Group(
					"after",
					slog.Int("used", 0),
					slog.Int("offset", len),
					slog.Int("cap", cache.cap),
				),
			)

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
			slog.Debug(
				"no sufficent space for new data, make new:",
				slog.Group(
					"before",
					slog.Int("used", cache.used),
					slog.Int("offset", cache.offset),
					slog.Int("cap", cache.cap),
				),
				slog.Int("data", size),
				slog.Int("new_cap", newCap),
				slog.Group(
					"after",
					slog.Int("used", 0),
					slog.Int("offset", cache.offset-cache.used),
					slog.Int("cap", newCap),
				),
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
	if used >= cache.Len() {
		slog.Debug(
			"all remain buffer rotated:",
			slog.Group(
				"before",
				slog.Int("used", cache.used),
				slog.Int("offset", cache.offset),
				slog.Int("cap", cache.cap),
			),
			slog.Int("rotate", used),
			slog.Group(
				"after",
				slog.Int("used", 0),
				slog.Int("offset", 0),
				slog.Int("cap", cache.cap),
			),
		)

		cache.used = 0
		cache.offset = 0
	} else {
		slog.Debug(
			"used size rotated:",
			slog.Group(
				"before",
				slog.Int("used", cache.used),
				slog.Int("offset", cache.offset),
				slog.Int("cap", cache.cap),
			),
			slog.Int("rotate", used),
			slog.Group(
				"after",
				slog.Int("used", cache.used+used),
				slog.Int("offset", cache.offset),
				slog.Int("cap", cache.cap),
			),
		)
		cache.used += used
	}

	cache.append(data)
}

// Bytes 返回剩余未使用字节数组
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

	cache.append(data)
	slog.Debug(
		"new data merged:",
		slog.Group(
			"cache",
			slog.Int("used", cache.used),
			slog.Int("offset", cache.offset),
			slog.Int("cap", cache.cap),
		),
		slog.Int("data", len(data)),
	)

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

func GetStreamCache(session *Session) *StreamCache {
	key := session.String()

	cache, exist := defaultStreamCaches[key]
	if !exist {
		cache = NewStreamCache()
		defaultStreamCaches[key] = cache
	}

	return cache
}
