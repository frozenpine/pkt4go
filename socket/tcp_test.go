package socket

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/frozenpine/pkt4go/core"
)

func TestDialTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	addr := "localhost:65500"

	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	run := atomic.Bool{}
	run.Store(true)
	defer func() {
		run.Store(false)
		l.Close()
	}()

	go func() {
		for run.Load() {
			select {
			case <-ctx.Done():
				return
			default:
				c, err := l.Accept()

				if err != nil {
					t.Log(err)
					continue
				}

				c.Write([]byte(fmt.Sprintf("hello %s", c.RemoteAddr())))
				c.Close()
			}
		}
	}()

	if err := DialTCP(ctx, addr, 0, func(session *core.Session, ts time.Time, data []byte) (int, error) {
		t.Log(session, ts, string(data))
		return len(data), nil
	}); err != nil {
		t.Fatal(err)
	}
}
