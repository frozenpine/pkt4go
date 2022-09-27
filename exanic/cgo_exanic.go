//go:build linux

package exanic

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -L./libs -lexanic

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
	defaultPktBufferLen = 100
)

type Device struct {
	handler *C.exanic_t
	port    int
}

func CreateHandler(src string) (*Device, error) {
	if src == "" {
		return nil, errors.New("device can not be empty")
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

	var rx *C.exanic_rx_t

	if filter != "" {
		rx = C.exanic_acquire_unused_filter_buffer(dev.handler, C.int(dev.port))
		if rx == nil {
			return errors.New("accquire rx buffer failed")
		}

		exaFilter := createFilter(filter)
		if exaFilter != nil && C.exanic_filter_add_ip(dev.handler, rx, exaFilter) == -1 {
			return errors.Errorf("create filter failed: %s", C.GoString(C.exanic_get_last_error()))
		}
	} else {
		rx = C.exanic_acquire_rx_buffer(dev.handler, C.int(dev.port), 0)
	}

	// cBufferLen := pkt4go.GetMTU()
	// cBuffer := C.malloc(C.size_t(cBufferLen))

	defer func() {
		C.exanic_release_rx_buffer(rx)
		// C.free(cBuffer)
	}()

	pktCh := make(chan *pkt4go.IPv4Packet, defaultPktBufferLen)

	go func() {
		defer func() {
			close(pktCh)
		}()

		for {
			frm := pkt4go.CreateEtherFrame()

			var timestamp C.exanic_cycles32_t
			var tsps C.struct_timespec

			// size := C.exanic_receive_frame(
			// 	rx,
			// 	(*C.char)(cBuffer),
			// 	C.size_t(cBufferLen),
			// 	&timestamp,
			// )
			size := C.exanic_receive_frame(
				rx,
				(*C.char)(unsafe.Pointer(&frm.Buffer[0])),
				C.size_t(len(frm.Buffer)),
				&timestamp,
			)

			if size <= 0 {
				frm.Release()
				continue
			}

			/*
				NOTE:
				sync host time / PPS to exanic first, to correct UNIX epoch

				REF:
				https://exablaze.com/docs/exanic/user-guide/clock-sync/

				EXAMPLE:
				# exanic-clock-sync exanic0:host
			*/
			expandTs := C.exanic_expand_timestamp(dev.handler, timestamp)
			C.exanic_cycles_to_timespec(dev.handler, expandTs, &tsps)
			frm.Timestamp = time.Unix(
				int64(tsps.tv_sec), int64(tsps.tv_nsec),
			)
			// frm.Buffer = C.GoBytes(cBuffer, C.int(size))
			frm.Buffer = frm.Buffer[:size]

			if err := frm.Unpack(frm.Buffer); err != nil {
				log.Printf("unpack eth header failed: %v", err)
				log.Printf("%+v", frm)
				frm.Release()
				continue
			} else if frm.Type != pkt4go.ProtoIP {
				log.Printf("%s received ether frame[%04x]: %s -> %s", frm.Timestamp, frm.Type, frm.SrcHost, frm.DstHost)
				frm.Release()
				continue
			}

			pkt := pkt4go.CreateIPv4Packet(frm)

			if err := pkt.Unpack(frm.GetPayload()); err != nil {
				log.Printf("unpack ip header failed: %v", err)
				log.Printf("%+v", frm)
				pkt.Release()
				continue
			}

			// TODO: 排查可能的oom kill

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
