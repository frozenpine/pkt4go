//go:build linux

package exanic

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -L./libs -lexanic

#include <stdint.h>
#include <stdlib.h>

#include "exanic_version.h"
#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/filter.h>
#include <exanic/time.h>
#include <exanic/config.h>
*/
import "C"
import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/frozenpine/pkt4go"
)

const (
	defaultPktBufferLen = 100
	defaultTCPBufferLen = 1024 * 1024
)

type Device struct {
	handler *C.exanic_t
	port    int
}

func GetVersion() string {
	return "exanic: " + C.EXANIC_VERSION_TEXT
}

func createHandler(name string, port int) (*Device, error) {
	dev := Device{port: port}

	dev.handler = C.exanic_acquire_handle(C.CString(name))

	if dev.handler == nil {
		return nil, errors.New("acquire handler failed: " + name)
	}

	return &dev, nil
}

func GetHandlerByIfaceName(iface string) (*Device, error) {
	if iface == "" {
		return nil, errors.New("iface name can not be empty")
	}

	deviceBuff := make([]byte, 50)
	port := 0
	var rtn C.int

	if rtn = C.exanic_find_port_by_interface_name(
		C.CString(iface),
		(*C.char)(unsafe.Pointer(&deviceBuff[0])),
		C.size_t(len(deviceBuff)), (*C.int)(unsafe.Pointer(&port)),
	); rtn != 0 {
		return nil, errors.New("no device found by name: " + iface)
	}

	dev := string(deviceBuff[:bytes.IndexByte(deviceBuff, 0x0)])

	log.Printf("iface[%s] info: %s:%d", iface, dev, port)

	return createHandler(dev, port)
}

func CreateHandler(src string) (*Device, error) {
	if src == "" {
		return nil, errors.New("device can not be empty")
	}

	devData := strings.Split(src, ":")

	if len(devData) != 2 {
		return nil, errors.New("invalid device string: " + src)
	}

	port, err := strconv.Atoi(devData[1])
	if err != nil {
		return nil, errors.Wrap(err, "invalid port num")
	}

	return createHandler(devData[0], port)
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

	done := sync.WaitGroup{}

	done.Add(1)
	go func() {
		defer func() {
			close(pktCh)

			done.Done()
		}()

		for {
			frm := pkt4go.CreateEtherFrame()

			var timestamp C.exanic_cycles32_t
			var tsps C.struct_timespec

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

			pktCh <- pkt
		}
	}()

	var (
		segment        pkt4go.PktData
		err            error
		flowHash       uint64
		sessionBuffers = make(map[uint64][]byte)
		buffer         []byte
		bufferExist    bool
		src, dst       net.Addr
		usedSize       int
	)

RUN:
	for {
		select {
		case <-ctx.Done():
			break RUN
		case pkt := <-pktCh:
			if pkt == nil {
				break RUN
			}

			switch pkt.Protocol {
			case pkt4go.TCP:
				tcp := pkt4go.CreateTCPSegment(pkt)

				if err = tcp.Unpack(pkt.GetPayload()); err != nil {
					log.Printf("unpack tcp header failed: %v", err)

					goto RELEASE
				}

				segment = tcp
				flowHash = tcp.Flow().FastHash()

				if tcp.Flags.HasFlag(pkt4go.SYN | pkt4go.ACK) {
					sessionBuffers[flowHash] = make([]byte, 0, defaultTCPBufferLen)
					goto RELEASE
				}

				if tcp.Flags.HasFlag(pkt4go.FIN | pkt4go.ACK) {
					delete(sessionBuffers, flowHash)
					goto RELEASE
				}

				payload := tcp.GetPayload()

				if len(payload) <= 0 {
					goto RELEASE
				}

				if buffer, bufferExist = sessionBuffers[flowHash]; !bufferExist {
					goto RELEASE
				}

				buffer = append(buffer, payload...)

				src = &net.TCPAddr{
					IP: net.IPv4(
						pkt.SrcAddr[0], pkt.SrcAddr[1],
						pkt.SrcAddr[2], pkt.SrcAddr[3],
					),
					Port: int(tcp.SrcPort),
				}
				dst = &net.TCPAddr{
					IP: net.IPv4(
						pkt.DstAddr[0], pkt.DstAddr[1],
						pkt.DstAddr[2], pkt.DstAddr[3],
					),
					Port: int(tcp.DstPort),
				}
			case pkt4go.UDP:
				udp := pkt4go.CreateUDPSegment(pkt)

				if err = udp.Unpack(pkt.GetPayload()); err != nil {
					log.Printf("unpack udp header failed: %v", err)

					goto RELEASE
				}

				segment = udp
				flowHash = udp.Flow().FastHash()

				if buffer, bufferExist = sessionBuffers[flowHash]; bufferExist {
					buffer = append(buffer, segment.GetPayload()...)
				} else {
					buffer = segment.GetPayload()
				}

				src = &net.TCPAddr{
					IP: net.IPv4(
						pkt.SrcAddr[0], pkt.SrcAddr[1],
						pkt.SrcAddr[2], pkt.SrcAddr[3],
					),
					Port: int(udp.SrcPort),
				}
				dst = &net.TCPAddr{
					IP: net.IPv4(
						pkt.DstAddr[0], pkt.DstAddr[1],
						pkt.DstAddr[2], pkt.DstAddr[3],
					),
					Port: int(udp.DstPort),
				}
			default:
				log.Printf("unsuppored transport: %x", pkt.Protocol)

				goto RELEASE
			}

			usedSize, err = fn(src, dst, segment.GetTimestamp(), buffer)

			if err != nil {
				if err == io.EOF {
					segment.Release()
					return nil
				}

				log.Printf("payload handler error: %v", err)
			} else if len(buffer) > usedSize {
				sessionBuffers[flowHash] = buffer[usedSize:]
			}

		RELEASE:
			segment.Release()
		}
	}

	done.Wait()

	return nil
}
