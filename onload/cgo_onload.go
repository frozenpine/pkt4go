//go:build linux

package onload

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -L./lib -lciul1

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>

#include <etherfabric/base.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>
#include <etherfabric/packedstream.h>
#include <etherfabric/memreg.h>

static inline int get_ef_event_poll(struct ef_vi *evq, ef_event *evs, int evs_len)
{
    return ef_eventq_poll(evq, evs, evs_len);
}

static inline u_int16_t get_ef_event_type(ef_event *evt)
{
    return EF_EVENT_TYPE(*evt);
}

static inline bool test_event_rx_ps_next_buffer(ef_event *evt)
{
    return EF_EVENT_RX_PS_NEXT_BUFFER(*evt);
}
*/
import "C"
import (
	"context"
	"io"
	"log"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/frozenpine/pkt4go"
	"github.com/pkg/errors"
)

func GetVersion() string {
	return C.GoString(C.ef_vi_version_str())
}

func GetInterfaceVersion() string {
	return C.GoString(C.ef_vi_driver_interface_str())
}

const (
	defaultFlags C.enum_ef_vi_flags = C.EF_VI_RX_PACKED_STREAM | C.EF_VI_RX_PS_BUF_SIZE_64K | C.EF_VI_RX_TIMESTAMPS
	// maxEvents * EF_VI_RX_PS_BUF_SIZE_64K * 2
	defaultHugePageSize int64 = 2 * 16 * 64 * 1024
	defaultPktBufferLen       = 100
	defaultTCPBufferLen       = 1024 * 1024
	maxEvents                 = 16
)

var (
	flags        C.enum_ef_vi_flags = defaultFlags
	hugePageSize int64              = defaultHugePageSize
	verbose                         = false
)

type buffer struct {
	efAddr C.ef_addr
	next   *buffer
}

type Device struct {
	dh                C.ef_driver_handle
	pd                C.struct_ef_pd
	vi                C.struct_ef_vi
	psp               C.ef_packed_stream_params
	memreg            C.struct_ef_memreg
	pspStartOffset    C.int
	currentBuffer     *buffer
	postedBuffers     *buffer
	postedBuffersTail **buffer
	psPktIter         *C.ef_packed_stream_packet
	rxPkts            uint64
	rxBytes           uint64
}

func (dev *Device) closeDH() {
	C.ef_driver_close(dev.dh)
}

func (dev *Device) freePD() {
	C.ef_pd_free(&dev.pd, dev.dh)
}

func (dev *Device) freeVI() {
	C.ef_vi_free(&dev.vi, dev.dh)
}

func (dev *Device) Release() {
	dev.freeVI()

	dev.freePD()

	dev.closeDH()
}

func (dev *Device) putPostedBuffer(buf *buffer) {
	buf.next = nil

	*dev.postedBuffersTail = buf

	dev.postedBuffersTail = &buf.next
}

func (dev *Device) getPostedBuffer() *buffer {
	buf := dev.postedBuffers

	if buf != nil {
		dev.postedBuffers = buf.next

		if dev.postedBuffers == nil {
			dev.postedBuffersTail = &dev.postedBuffers
		}
	}

	return buf
}

// EventType Possible types of events
type EFEventType uint16

const (
	// Good data was received
	EF_EVENT_TYPE_RX EFEventType = iota
	// Packets have been sent
	EF_EVENT_TYPE_TX
	// Data received and buffer consumed, but something is wrong
	EF_EVENT_TYPE_RX_DISCARD
	// Transmit of packet failed
	EF_EVENT_TYPE_TX_ERROR
	// Received packet was truncated due to a lack of descriptors
	EF_EVENT_TYPE_RX_NO_DESC_TRUNC
	// Software generated event
	EF_EVENT_TYPE_SW
	// Event queue overflow
	EF_EVENT_TYPE_OFLOW
	// TX timestamp event
	EF_EVENT_TYPE_TX_WITH_TIMESTAMP
	// A batch of packets was received in a packed stream
	EF_EVENT_TYPE_RX_PACKED_STREAM
	// A batch of packets was received on a RX event merge vi
	EF_EVENT_TYPE_RX_MULTI
	// Packet has been transmitted via a "TX alternative"
	EF_EVENT_TYPE_TX_ALT
	// A batch of packets was received with error condition set
	EF_EVENT_TYPE_RX_MULTI_DISCARD
	// Event queue has been forcibly halted (hotplug, reset, etc.)
	EF_EVENT_TYPE_RESET
)

// EFEventFlags event flags
type EFEventFlags uint16

const (
	/* RX-event flags. */

	// Start Of Packet flag
	EF_EVENT_FLAG_SOP EFEventFlags = 0x1 << iota
	// CONTinuation Of Packet flag
	EF_EVENT_FLAG_CONT
	// iSCSI CRC validated OK flag
	EF_EVENT_FLAG_ISCSI_OK
	// Multicast flag
	EF_EVENT_FLAG_MULTICAST
	// Packed Stream Next Buffer flag
	EF_EVENT_FLAG_PS_NEXT_BUFFER

	/* TX-event flags. */
	// Packets were sent successfully with CTPIO
	EF_EVENT_FLAG_CTPIO EFEventFlags = 0x1
)

func CreateHandler(src string) (*Device, error) {
	if src == "" {
		return nil, errors.New("device can not be empty")
	}

	dev := Device{}

	if C.ef_driver_open(&dev.dh) != 0 {
		return nil, errors.New("driver open failed")
	}

	if C.ef_pd_alloc_by_name(
		&dev.pd,
		dev.dh,
		C.CString(src),
		C.EF_PD_RX_PACKED_STREAM,
	) != 0 {
		dev.closeDH()

		return nil, errors.New("alloc protect domain failed")
	}

	if C.ef_vi_alloc_from_pd(
		&dev.vi, dev.dh,
		&dev.pd, dev.dh,
		-1, -1, -1, nil, -1,
		defaultFlags,
	) < 0 {
		dev.freePD()
		dev.closeDH()

		return nil, errors.New("alloc virtual interface faile")
	}

	if C.ef_vi_packed_stream_get_params(&dev.vi, &dev.psp) != 0 {
		dev.freeVI()
		dev.freePD()
		dev.closeDH()

		return nil, errors.New("get packed stream params failed")
	}

	// TODO: mmap huge page for rx cache

	return &dev, nil
}

func createFilter(input string) *C.ef_filter_spec {
	if input == "" {
		return nil
	}

	var filter C.ef_filter_spec

	return &filter
}

func StartCapture(ctx context.Context, dev *Device, filter string, fn pkt4go.DataHandler) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	defer dev.Release()

	if efviFilter := createFilter(filter); efviFilter != nil {
		if C.ef_vi_filter_add(&dev.vi, dev.dh, efviFilter, nil) < 0 {
			return errors.New("add filter failed")
		}
	}

	pktCh := make(chan *pkt4go.IPv4Packet, defaultPktBufferLen)
	events := [maxEvents]C.ef_event{}

	done := sync.WaitGroup{}

	done.Add(1)
	go func() {
		defer func() {
			close(pktCh)

			done.Done()
		}()

		var nPkts, nBytes, rc C.int

	CAPTURE:
		for {
			select {
			case <-ctx.Done():
				return
			default:
				evtCount := int(C.get_ef_event_poll(&dev.vi, (*C.ef_event)(unsafe.Pointer(&events[0])), maxEvents))

				for idx := 0; idx < evtCount; idx++ {
					evt := (*C.ef_event)(unsafe.Pointer(&events[idx]))
					evtType := EFEventType(C.get_ef_event_type(evt))

					switch evtType {
					case EF_EVENT_TYPE_RX_PACKED_STREAM:
						if bool(C.test_event_rx_ps_next_buffer(evt)) {
							if dev.currentBuffer != nil {
								if rtn := int(C.ef_vi_receive_post(&dev.vi, dev.currentBuffer.efAddr, 0)); rtn < 0 {
									err = errors.Errorf("receive data failed: rc=%d, errno=%d, (%s)", rtn)
									break CAPTURE
								}

								dev.putPostedBuffer(dev.currentBuffer)
							}

							dev.currentBuffer = dev.getPostedBuffer()
							dev.psPktIter = C.ef_packed_stream_packet_first(unsafe.Pointer(dev.currentBuffer), dev.pspStartOffset)
						}

						psPkt := dev.psPktIter
						rc = C.ef_vi_packed_stream_unbundle(&dev.vi, evt, &dev.psPktIter, &nPkts, &nBytes)
						if verbose {
							log.Printf("Event: rc=%d n_pkts=%d n_bytes=%d\n", rc, nPkts, nBytes)
						}

						dev.rxPkts += uint64(nPkts)
						dev.rxBytes += uint64(nBytes)

						for count := 0; count < int(nPkts); count++ {
							payloadPtr := C.ef_packed_stream_packet_payload(psPkt)
							len := int(psPkt.ps_cap_len)
							payload := (*[]byte)(unsafe.Pointer(&reflect.SliceHeader{Data: uintptr(payloadPtr), Len: len, Cap: len}))

							frm := pkt4go.CreateEtherFrame(*payload, time.Unix(int64(psPkt.ps_ts_sec), int64(psPkt.ps_ts_nsec)))

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

							psPkt = C.ef_packed_stream_packet_next(psPkt)
						}
					default:
						log.Printf("Unexpected event type: %d", evtType)
					}
				}
			}
		}
	}()

	var (
		segment        pkt4go.PktData
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

				src = &net.UDPAddr{
					IP: net.IPv4(
						pkt.SrcAddr[0], pkt.SrcAddr[1],
						pkt.SrcAddr[2], pkt.SrcAddr[3],
					),
					Port: int(udp.SrcPort),
				}
				dst = &net.UDPAddr{
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

	return
}
