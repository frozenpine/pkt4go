package socket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/frozenpine/pkt4go/core"
)

const (
	defaultBuffSize = 4096
)

func DialTCP(ctx context.Context, front string, buffSize int, handler core.DataHandler) error {
	if handler == nil {
		return errors.New("data handler can not be nil")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	addr, err := net.ResolveTCPAddr("tcp", front)
	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if buffSize <= 0 {
		buffSize = defaultBuffSize
	}

	local := strings.Split(conn.LocalAddr().String(), ":")
	localIP := net.ParseIP(strings.Trim(local[0], "[]"))
	localPort, _ := strconv.Atoi(local[1])

	remote := strings.Split(conn.RemoteAddr().String(), ":")
	remoteIP := net.ParseIP(strings.Trim(remote[0], "[]"))
	remotePort, _ := strconv.Atoi(remote[1])

	cache := core.NewStreamCache()
	session := core.Session{
		Proto:   core.TCP,
		SrcIP:   remoteIP,
		SrcPort: remotePort,
		DstIP:   localIP,
		DstPort: localPort,
	}

	buff := make([]byte, buffSize)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, err := conn.Read(buff)
			ts := time.Now()

			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}

				return err
			}

			buff = cache.Merge(buff[:n])
			used, err := handler(&session, ts, buff)

			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}

				return fmt.Errorf(
					"[%s] %s data handler failed: %w",
					ts, &session, err)
			}

			size := len(buff)

			if used < 0 {
				log.Printf("handler return size invalid: %d", used)
				continue
			}

			if remain := cache.Append(buff[used:]); remain > 0 {
				log.Printf(
					"%s handler result: New[%d], Used[%d], Remain[%d]",
					&session, size, used, remain,
				)
			}
		}
	}
}
