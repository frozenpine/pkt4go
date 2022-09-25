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
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/frozenpine/pkt4go"
)

const (
	defaultBufferLen    = 4096
	defaultPktBufferLen = 100

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

	pktCh := make(chan *pkt4go.IPv4Packet, defaultPktBufferLen)

	go func() {
		defer func() {
			close(pktCh)
		}()

		for {
			frm := pkt4go.CreateEtherFrame()

			var timestamp C.exanic_cycles32_t
			var tsps C.struct_timespec

			size := C.exanic_receive_frame(
				rx,
				(*C.char)(unsafe.Pointer(&frm.Buffer)),
				C.size_t(defaultBufferLen),
				&timestamp,
			)

			if size < 0 {
				frm.Release()
				continue
			}

			// TODO: ether frame unpack and data check

			expandTs := C.exanic_expand_timestamp(dev.handler, timestamp)
			C.exanic_cycles_to_timespec(dev.handler, expandTs, &tsps)
			frm.Timestamp = time.Unix(
				int64(tsps.tv_sec), int64(tsps.tv_nsec),
			)

			pkt := pkt4go.CreateIPv4Packet(frm)

			if err := pkt.Unpack(frm.GetPayload()); err != nil {
				log.Printf("unpack ip header failed: %v", err)
				pkt.Release()
				continue
			}

			pktCh <- pkt
		}
	}()

	var (
		// sessionCache = make(map[uint64][]byte)
		segment pkt4go.PktData
		err     error
		// srcIP, dstIP     pkt4go.IPv4Addr
		// srcPort, dstPort pkt4go.Port
	)

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt := <-pktCh:
			if pkt == nil {
				return nil
			}

			switch pkt.Protocol {
			case pkt4go.TCP:
				tcp := pkt4go.CreateTCPSegment(pkt)
				segment = tcp

				if err = tcp.Unpack(pkt.GetPayload()); err != nil {
					log.Printf("unpack tcp header failed: %v", err)
					goto RELEASE
				}
			case pkt4go.UDP:
				udp := pkt4go.CreateUDPSegment(pkt)
				segment = udp

				if err = udp.Unpack(pkt.GetPayload()); err != nil {
					log.Printf("unpack udp header failed: %v", err)
					goto RELEASE
				}
			default:
				log.Printf("unsuppored transport: %x", pkt.Protocol)
				pkt.Release()
				continue
			}

			// fn(pkg.src, pkg.dst, pkg.payload)

		RELEASE:
			segment.Release()
		}
	}
}
