package cache

type StickyCache struct {
	cache []byte
}

func (c *StickyCache) Append(buff *Buffer) {
	if buff == nil || buff.Len() <= 0 {
		return
	}

	c.cache = append(c.cache, buff.Bytes()...)
}
