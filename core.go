package pkg4go

import "net"

type DataHandler func(src, dst net.Addr, data []byte) (int, error)
