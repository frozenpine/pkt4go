// Code generated by "stringer -type TCPFlags -linecomment"; DO NOT EDIT.

package core

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[FIN-1]
	_ = x[SYN-2]
	_ = x[RST-4]
	_ = x[PUS-8]
	_ = x[ACK-16]
	_ = x[URG-32]
	_ = x[ECE-64]
	_ = x[CWR-128]
}

const (
	_TCPFlags_name_0 = "finishsync"
	_TCPFlags_name_1 = "reset"
	_TCPFlags_name_2 = "push"
	_TCPFlags_name_3 = "acknowlege"
	_TCPFlags_name_4 = "urgent"
	_TCPFlags_name_5 = "ece"
	_TCPFlags_name_6 = "cwr"
)

var (
	_TCPFlags_index_0 = [...]uint8{0, 6, 10}
)

func (i TCPFlags) String() string {
	switch {
	case 1 <= i && i <= 2:
		i -= 1
		return _TCPFlags_name_0[_TCPFlags_index_0[i]:_TCPFlags_index_0[i+1]]
	case i == 4:
		return _TCPFlags_name_1
	case i == 8:
		return _TCPFlags_name_2
	case i == 16:
		return _TCPFlags_name_3
	case i == 32:
		return _TCPFlags_name_4
	case i == 64:
		return _TCPFlags_name_5
	case i == 128:
		return _TCPFlags_name_6
	default:
		return "TCPFlags(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
