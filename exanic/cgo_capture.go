//go:build linux

package exanic

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -lexanic

#include <stdint.h>
#include <stdlib.h>

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/filter.h>
#include <exanic/time.h>
#include "exanic_version.h"
*/
import "C"
import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/frozenpine/pkt4go"
)

const (
	defaultBufferLen    = 4096
	defaultPkgBufferLen = 100

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
		return nil, errors.New("invalid device string: " + src)
	}

	var dev Device
	var err error

	dev.port, err = strconv.Atoi(devData[1])
	if err != nil {
		return nil, errors.Wrap(err, "invalid port num")
	}

	dev.handler = C.exanic_acquire_handle(C.CString(devData[0]))

	if dev.handler == nil {
		return nil, errors.New("acquire handler failed: " + devData[0])
	}

	return &dev, nil
}

func createFilter(input string) *C.exanic_ip_filter_t {
	if input == "" {
		return nil
	}

	var filter C.exanic_ip_filter_t

	return &filter
}

type IPv4Packet struct {
	Header    *pkt4go.IPv4Header
	Payload   []byte
	Timestamp time.Time
}

type TCPSegment struct {
	Header  *pkt4go.TCPHeader
	Payload []byte
}

type UDPSegment struct {
	Header  *pkt4go.UDPHeader
	Payload []byte
}

var (
	MTU            = 1500
	ipv4HeaderPool = sync.Pool{New: func() any { return &pkt4go.IPv4Header{} }}
	tcpHeaderPool  = sync.Pool{New: func() any { return &pkt4go.TCPHeader{} }}
	udpHeaderPool  = sync.Pool{New: func() any { return &pkt4go.UDPHeader{} }}
	payloadPool    = sync.Pool{New: func() any { return make([]byte, 0, MTU) }}
)

func GetIPv4Packet() *IPv4Packet {
	return &IPv4Packet{
		Header:  ipv4HeaderPool.Get().(*pkt4go.IPv4Header),
		Payload: payloadPool.Get().([]byte),
	}
}

func ReleaseIPv4Packet(pkt *IPv4Packet) {
	ipv4HeaderPool.Put(pkt.Header)
	payloadPool.Put(pkt.Payload[:0])
}

func StartCapture(ctx context.Context, dev *Device, filter string, fn pkt4go.DataHandler) error {
	if ctx == nil {
		ctx = context.Background()
	}

	defer func() {
		C.exanic_release_handle(dev.handler)
	}()

	rx := C.exanic_acquire_unused_filter_buffer(dev.handler, C.int(dev.port))
	if rx == nil {
		return errors.New("accquire rx buffer failed")
	}
	defer func() {
		C.exanic_release_rx_buffer(rx)
	}()

	exaFilter := createFilter(filter)
	if exaFilter != nil && C.exanic_filter_add_ip(dev.handler, rx, exaFilter) == -1 {
		return errors.Errorf("create filter failed: %s", C.GoString(C.exanic_get_last_error()))
	}

	pktCh := make(chan *IPv4Packet, defaultPkgBufferLen)

	go func() {
		defer func() {
			close(pktCh)
		}()

		for {
			data := GetIPv4Packet()

			var timestamp C.exanic_cycles32_t
			var tsps C.struct_timespec

			size := C.exanic_receive_frame(
				rx,
				(*C.char)(unsafe.Pointer(&data.Payload)),
				C.size_t(defaultBufferLen),
				&timestamp,
			)

			if size < 0 {
				ReleaseIPv4Packet(data)
				continue
			}

			expandTs := C.exanic_expand_timestamp(dev.handler, timestamp)
			C.exanic_cycles_to_timespec(dev.handler, expandTs, &tsps)
			data.Timestamp = time.Unix(int64(tsps.tv_sec), int64(tsps.tv_nsec))

			if err := data.Header.Unpack(data.Payload[pkt4go.EtherHeaderSize:]); err != nil {
				log.Printf("unpack ip header failed: %v", err)
				ReleaseIPv4Packet(data)
				continue
			}

			pktCh <- data
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt := <-pktCh:
			if pkt == nil {
				return nil
			}

			// fn(pkg.src, pkg.dst, pkg.payload)

			ReleaseIPv4Packet(pkt)
		}
	}
}
