package pkg4go

import (
	"net"
	"time"
)

type DataHandler func(src, dst net.Addr, data []byte) (int, error)

var (
	defaultTimeZone, _ = time.LoadLocation("Local")
)
