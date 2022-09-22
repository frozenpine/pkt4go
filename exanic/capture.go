//go:build linux

package exanic

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lexanic

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
*/
import "C"
import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/frozenpine/pkg4go"
)

const (
	defaultBufferLen    = 4096
	defaultPkgBufferLen = 100
	defaultBufferNum    = 0

	PORT_KEY = "port"
)

type Device struct {
	handler *C.exanic_t
	port    int
}

func CreateHandler(src string) (*Device, error) {
	if src == "" {
		return nil, errors.New("device can not be enpty")
	}

	devData := strings.Split(src, ":")

	if len(devData) != 2 {
		return nil, errors.New("invalid device string")
	}

	var dev Device
	var err error

	dev.port, err = strconv.Atoi(devData[1])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dev.handler = C.exanic_acquire_handle(C.CString(src))

	if dev.handler == nil {
		return nil, errors.New("acquire handler failed")
	}

	return &dev, nil
}

type pkgData struct {
	src    net.Addr
	dst    net.Addr
	buffer []byte
}

func StartCapture(ctx context.Context, dev *Device, filter string, fn pkg4go.DataHandler) error {
	if ctx == nil {
		ctx = context.Background()
	}

	rx := C.exanic_acquire_rx_buffer(dev.handler, C.int(dev.port), defaultBufferNum)
	if rx == nil {
		return errors.New("accquire rx buffer failed")
	}

	buffer := [defaultBufferLen]byte{}
	var timestamp C.exanic_cycles32_t

	pkgCh := make(chan *pkgData, defaultPkgBufferLen)

	go func() {
		size := C.exanic_receive_frame(
			rx,
			(*C.char)(unsafe.Pointer(&buffer)),
			C.size_t(defaultBufferLen),
			&timestamp,
		)

		pkgCh <- &pkgData{
			src:    nil,
			dst:    nil,
			buffer: buffer[:size],
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkg := <-pkgCh:
			if pkg == nil {
				return nil
			}

			log.Printf("src[%s], dst[%s], %v", pkg.src, pkg.dst, pkg.buffer)
		}
	}
}
