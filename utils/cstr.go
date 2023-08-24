package utils

import (
	"bytes"
)

func findCStrTerm(in []byte) (idx int) {
	idx = bytes.IndexByte(in, 0x0)

	if idx < 0 {
		idx = 0
	}

	return
}

func CStr2GoStr(in []byte) string {
	return string(in[:findCStrTerm(in)])
}
