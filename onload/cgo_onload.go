//go:build linux

package onload

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -L./libs -lciul1

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include <etherfabric/base.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>
#include <etherfabric/memreg.h>

typedef struct pkt_buf
{
	// I/O address corresponding to the start of this pkt_buf struct
	ef_addr ef_addr;

	// pointer to where received packets start
	void *rx_ptr;

	int id;
	struct pkt_buf *next;
} pkt_buf_t;

static inline int get_errno()
{
	return errno;
}

static inline uint64_t round_up(int p, int align)
{
    return ((p) + (align)-1u) & ~((align)-1u);
}

#define RX_DMA_OFF round_up(sizeof(struct pkt_buf), EF_VI_DMA_ALIGN)

// execution wrapper for macro ef_vi_receive_init
static inline void exec_ef_vi_receive_init(struct ef_vi *vi, void *addr, int dma_id)
{
	ef_vi_receive_init(vi, addr, dma_id);
}

// execution wrapper for macro ef_vi_receive_push
static inline void exec_ef_vi_receive_push(struct ef_vi *vi)
{
	ef_vi_receive_push(vi);
}

// execution wrapper for macro ef_eventq_poll
static inline int exec_ef_event_poll(struct ef_vi *evq, ef_event *evs, int evs_len)
{
    return ef_eventq_poll(evq, evs, evs_len);
}

// execution wrapper for macro EF_EVENT_TYPE
// Type of event in an ef_event e
static inline uint16_t get_ef_event_type(ef_event *evt)
{
    return EF_EVENT_TYPE(*evt);
}

// execution wrapper for macro EF_EVENT_RX_SOP
// True if the Start Of Packet flag is set for an RX event
static inline uint16_t get_ef_event_rx_sop(ef_event *evt)
{
	return EF_EVENT_RX_SOP(*evt);
}

// execution wrapper for macro EF_EVENT_RX_CONT
// True if the CONTinuation Of Packet flag is set for an RX event
static inline uint16_t get_ef_event_rx_cont(ef_event *evt)
{
	return EF_EVENT_RX_CONT(*evt);
}

// execution wrapper for macro EF_EVENT_RX_MULTI_SOP
// True if the Start Of Packet flag is set for an RX HT event
static inline uint16_t get_ef_event_rx_multi_sop(ef_event *evt)
{
	return EF_EVENT_RX_MULTI_SOP(*evt);
}

// execution wrapper for macro EF_EVENT_RX_MULTI_CONT
// True if the CONTinuation Of Packet flag is set for an RX HT event
static inline uint16_t get_ef_event_rx_multi_cont(ef_event *evt)
{
	return EF_EVENT_RX_MULTI_CONT(*evt);
}

// execution wrapper for macro EF_EVENT_RX_RQ_ID
// Get the dma_id used for a received packet
static inline uint32_t get_ef_event_rx_rq_id(ef_event *evt)
{
    return EF_EVENT_RX_RQ_ID(*evt);
}

// execution wrapper for macro EF_EVENT_RX_BYTES
// Get the number of bytes received
static inline int get_ef_event_rx_bytes(ef_event *evt)
{
    return EF_EVENT_RX_BYTES(*evt);
}

// execution wrapper for macro EF_EVENT_RX_DISCARD_RQ_ID
// Get the dma_id used for a discarded packet
static inline uint32_t get_ef_event_rx_discard_rq_id(ef_event *evt)
{
    return EF_EVENT_RX_DISCARD_RQ_ID(*evt);
}

// execution wrapper for macro EF_EVENT_RX_DISCARD_BYTES
// Get the length of a discarded packet
static inline int get_ef_event_rx_discard_bytes(ef_event *evt)
{
    return EF_EVENT_RX_DISCARD_BYTES(*evt);
}

// execution wrapper for macro EF_EVENT_RX_DISCARD_TYPE
// Get the reason for an EF_EVENT_TYPE_RX_DISCARD event
static inline uint16_t get_ef_event_rx_discard_type(ef_event *evt)
{
    return EF_EVENT_RX_DISCARD_TYPE(*evt);
}
*/
import "C"
import (
	"context"
	"fmt"
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
	defaultFlags        C.enum_ef_vi_flags = C.EF_VI_FLAGS_DEFAULT | C.EF_VI_RX_TIMESTAMPS
	defaultHugePageSize int64              = 2 * 1024 * 1024

	EV_POLL_BATCH_SIZE      = 16
	REFILL_BATCH_SIZE       = 16
	PKT_BUF_SIZE            = 2048
	EF_VI_RECEIVE_BATCH int = int(C.EF_VI_RECEIVE_BATCH)

	defaultPktBufferLen = 100
	defaultTCPBufferLen = 1024 * 1024
)

var (
	flags        C.enum_ef_vi_flags = defaultFlags
	hugePageSize                    = defaultHugePageSize

	verbose = false
)

func try(rtn C.int) error {
	if rtn < 0 {
		errno := C.get_errno()

		return fmt.Errorf("rc=%d errno=%d (%s)", rtn, errno, C.GoString(C.strerror(errno)))
	}

	return nil
}

type Device struct {
	/* handle for accessing the driver */
	dh C.ef_driver_handle

	/* protection domain */
	pd C.struct_ef_pd

	/* virtual interface (rxq + txq) */
	vi                        C.struct_ef_vi
	rxPrefixLen, pktLenOffset C.int
	refillLevel, refillMin    C.int
	batchLoops                int

	/* registered memory for DMA */
	nBufs   C.int
	evqSize C.int
	pktBufs unsafe.Pointer
	memreg  C.struct_ef_memreg

	/* pool of free packet buffers (LIFO to minimise working set) */
	freePktBufs  *C.pkt_buf_t
	nFreePktBufs int

	/* statistics */
	rxPkts  uint64
	rxBytes uint64
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

func (dev *Device) pktBufFromID(idx int) (*C.pkt_buf_t, error) {
	if idx >= int(dev.nBufs) {
		return nil, fmt.Errorf("buffer idx exceeded")
	}

	return (*C.pkt_buf_t)(
		unsafe.Pointer(
			uintptr(dev.pktBufs) + uintptr(idx*PKT_BUF_SIZE),
		)), nil
}

func (dev *Device) releasePktBuf(pktBuf *C.pkt_buf_t) {
	pktBuf.next = dev.freePktBufs
	dev.freePktBufs = pktBuf
	dev.nFreePktBufs++
}

func (dev *Device) handleRx(pktBufIdx, len int) error {
	pktBuf, err := dev.pktBufFromID(pktBufIdx)
	if err != nil {
		return err
	}

	var (
		hwTS    C.struct_timespec
		tsFlags C.uint
	)

	dmaPtr := unsafe.Pointer(
		uintptr(unsafe.Pointer(pktBuf)) + uintptr(C.RX_DMA_OFF),
	)

	if err := try(C.ef_vi_receive_get_timestamp_with_sync_flags(
		&dev.vi, dmaPtr, &hwTS, &tsFlags,
	)); err != nil {
		return err
	}

	ts := time.Unix(int64(hwTS.tv_sec), int64(hwTS.tv_nsec))
	payload := *(*[]byte)(unsafe.Pointer(
		&reflect.SliceHeader{
			Data: uintptr(pktBuf.rx_ptr),
			Len:  len, Cap: len,
		},
	))

	frm := pkt4go.CreateEtherFrame(payload, ts)
	frm.DelegateRelease(func() {
		dev.releasePktBuf(pktBuf)
	})

	if err := frm.Unpack(frm.Buffer); err != nil {
		frm.Release()
		return err
	} else if frm.Type != pkt4go.ProtoIP {
		log.Printf("%s received ether frame[%04x]: %s -> %s", frm.Timestamp, frm.Type, frm.SrcHost, frm.DstHost)
		frm.Release()
	}

	pkt := pkt4go.CreateIPv4Packet(frm)

	if err := pkt.Unpack(frm.GetPayload()); err != nil {
		pkt.Release()
		return err
	}

	// TODO: channel notify
	dev.rxPkts += 1
	dev.rxBytes += uint64(len)

	return nil
}

func (dev *Device) handleBatchRx(pktBufIdx int) error {
	pktBuf, err := dev.pktBufFromID(pktBufIdx)
	if err != nil {
		return err
	}

	dmaPtr := uintptr(unsafe.Pointer(pktBuf)) + uintptr(C.RX_DMA_OFF)

	dataLen := *(*uint16)(unsafe.Pointer(dmaPtr + uintptr(dev.pktLenOffset)))

	return dev.handleRx(pktBufIdx, int(dataLen))
}

func (dev *Device) handleRxDiscard(pktBufIdx, len int, typ EFRxDiscardType) error {
	if verbose {
		log.Printf("Packet discarded due to: %s", typ)
	}

	pktBuf, err := dev.pktBufFromID(pktBufIdx)
	if err != nil {
		return err
	}

	dev.releasePktBuf(pktBuf)

	return nil
}

func (dev *Device) refillRxRing() bool {
	if C.ef_vi_receive_fill_level(&dev.vi) > dev.refillLevel ||
		dev.nFreePktBufs < REFILL_BATCH_SIZE {
		return false
	}

	var pktBuf *C.pkt_buf_t

	for next := true; next; next = C.ef_vi_receive_fill_level(&dev.vi) < dev.refillMin && dev.nFreePktBufs >= REFILL_BATCH_SIZE {
		for i := 0; i < REFILL_BATCH_SIZE; i++ {
			pktBuf = dev.freePktBufs
			dev.freePktBufs = dev.freePktBufs.next
			dev.nFreePktBufs--
			C.exec_ef_vi_receive_init(&dev.vi, unsafe.Pointer(uintptr(pktBuf.ef_addr+C.RX_DMA_OFF)), pktBuf.id)
		}
	}

	C.exec_ef_vi_receive_push(&dev.vi)

	return true
}

func (dev *Device) pollEvq() (int, error) {
	events := [EV_POLL_BATCH_SIZE]C.ef_event{}
	IDs := [EF_VI_RECEIVE_BATCH]C.ef_request_id{}

	eventCount := int(C.exec_ef_event_poll(&dev.vi, (*C.ef_event)(unsafe.Pointer(&events[0])), EV_POLL_BATCH_SIZE))

	for idx := 0; idx < eventCount; idx++ {
		evt := &events[idx]
		evtType := EFEventType(C.get_ef_event_type(evt))

		switch evtType {
		case EF_EVENT_TYPE_RX:
			if C.get_ef_event_rx_sop(evt) == 0 || C.get_ef_event_rx_cont(evt) != 0 {
				return -1, errors.New("event rx[sop|cont] test failed")
			}

			dmaIdx := C.get_ef_event_rx_rq_id(evt)
			nBytes := C.get_ef_event_rx_bytes(evt)

			if err := dev.handleRx(int(dmaIdx), int(nBytes)); err != nil {
				return -1, err
			}
		case EF_EVENT_TYPE_RX_MULTI:
			goto MULTI
		case EF_EVENT_TYPE_RX_MULTI_DISCARD:
			goto MULTI
		case EF_EVENT_TYPE_RX_DISCARD:
			dmaIdx := int(C.get_ef_event_rx_discard_rq_id(evt))
			discardBytes := int(C.get_ef_event_rx_discard_bytes(evt) - dev.rxPrefixLen)
			discardType := EFRxDiscardType(C.get_ef_event_rx_discard_type(evt))

			if err := dev.handleRxDiscard(dmaIdx, discardBytes, discardType); err != nil {
				return -1, err
			}
		case EF_EVENT_TYPE_RESET:
			return -1, fmt.Errorf("NIC has been Reset and VI is no longer valid")
		default:
			log.Printf("unexpected event type: %d", evtType)
		}

		continue

	MULTI:
		if C.get_ef_event_rx_multi_sop(evt) == 0 || C.get_ef_event_rx_multi_cont(evt) != 0 {
			return -1, errors.New("event rx multi[sop|cont] test failed")
		}

		nRx := int(C.ef_vi_receive_unbundle(
			&dev.vi, evt, (*C.ef_request_id)(unsafe.Pointer(&IDs[0]))),
		)

		for idx := 0; idx < nRx; idx++ {
			dev.handleBatchRx(int(IDs[idx]))
		}
	}

	return eventCount, nil
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

type EFRxDiscardType uint16

const (
	/** IP header or TCP/UDP checksum error */
	EF_EVENT_RX_DISCARD_CSUM_BAD EFRxDiscardType = iota
	/** Hash mismatch in a multicast packet */
	EF_EVENT_RX_DISCARD_MCAST_MISMATCH
	/** Ethernet CRC error */
	EF_EVENT_RX_DISCARD_CRC_BAD
	/** Frame was truncated */
	EF_EVENT_RX_DISCARD_TRUNC
	/** No ownership rights for the packet */
	EF_EVENT_RX_DISCARD_RIGHTS
	/** Event queue error, previous RX event has been lost */
	EF_EVENT_RX_DISCARD_EV_ERROR
	/** Other unspecified reason */
	EF_EVENT_RX_DISCARD_OTHER
	/** Inner IP header or TCP/UDP checksum error */
	EF_EVENT_RX_DISCARD_INNER_CSUM_BAD
	/** Maximum value of this enumeration */
	/* Keep this last */
	EF_EVENT_RX_DISCARD_MAX
)

func CreateHandler(iface string) (*Device, error) {
	if iface == "" {
		return nil, errors.New("device can not be empty")
	}

	dev := Device{}

	if err := try(C.ef_driver_open(&dev.dh)); err != nil {
		return nil, errors.Wrap(err, "driver open failed")
	}

	if err := try(C.ef_pd_alloc_by_name(
		&dev.pd,
		dev.dh,
		C.CString(iface),
		C.EF_PD_DEFAULT,
	)); err != nil {
		dev.closeDH()

		return nil, errors.Wrap(err, "alloc protect domain failed")
	}

	if err := try(C.ef_vi_alloc_from_pd(
		&dev.vi, dev.dh,
		&dev.pd, dev.dh,
		-1, -1, 0, nil, -1,
		flags,
	)); err != nil {
		dev.freePD()
		dev.closeDH()

		return nil, errors.Wrap(err, "alloc virtual interface failed")
	}

	dev.rxPrefixLen = C.ef_vi_receive_prefix_len(&dev.vi)

	var layoutPtr *C.ef_vi_layout_entry
	var len C.int
	if err := try(C.ef_vi_receive_query_layout(&dev.vi, &layoutPtr, &len)); err != nil {
		return nil, errors.Wrap(err, "query layout failed")
	} else {
		layoutLen := int(len)
		layoutSlice := *(*[]*C.ef_vi_layout_entry)(unsafe.Pointer(&reflect.SliceHeader{
			Data: uintptr(unsafe.Pointer(layoutPtr)),
			Len:  layoutLen,
			Cap:  layoutLen,
		}))

		for _, layout := range layoutSlice {
			if layout.evle_type != C.EF_VI_LAYOUT_PACKET_LENGTH {
				continue
			}

			dev.pktLenOffset = layout.evle_offset
		}
	}

	dev.nBufs = C.ef_vi_receive_capacity(&dev.vi) - C.int(REFILL_BATCH_SIZE)
	dev.evqSize = C.ef_eventq_capacity(&dev.vi)

	if verbose {
		log.Printf(
			"max_fill=%d\nevq_size=%d\nrx_prefix_len=%d",
			dev.nBufs, dev.evqSize, dev.rxPrefixLen,
		)
	}

	allocSize := C.round_up(dev.nBufs*C.int(PKT_BUF_SIZE), C.int(hugePageSize))

	dev.pktBufs = C.mmap(nil, allocSize, C.PROT_READ|C.PROT_WRITE,
		/*MAP_ANONYMOUS |*/ C.MAP_PRIVATE|C.MAP_HUGETLB, -1, 0)
	if dev.pktBufs == C.MAP_FAILED {
		log.Printf("Require mmap failed, are huge pages configured?")

		/* Allocate huge-page-aligned memory to give best chance of allocating
		 * transparent huge-pages.
		 */
		if err := try(C.posix_memalign(&dev.pktBufs, C.ulong(hugePageSize), C.ulong(allocSize))); err != nil {
			return nil, errors.Wrap(err, "transparent huge-pages align failed")
		}
	}

	if err := try(C.ef_memreg_alloc(&dev.memreg, dev.dh, &dev.pd, dev.dh, dev.pktBufs, allocSize)); err != nil {
		return nil, errors.Wrap(err, "memreg alloc failed")
	}

	for idx := 0; idx < int(dev.nBufs); idx++ {
		buf, _ := dev.pktBufFromID(idx)

		buf.rx_ptr = unsafe.Pointer(
			uintptr(unsafe.Pointer(buf)) + uintptr(C.RX_DMA_OFF) + uintptr(dev.rxPrefixLen),
		)
		buf.id = C.int(idx)

		buf.ef_addr = C.ef_memreg_dma_addr(&dev.memreg, C.size_t(idx*PKT_BUF_SIZE))
	}

	dev.refillLevel = dev.nBufs - C.int(REFILL_BATCH_SIZE)
	dev.refillMin = dev.nBufs / 2

	for level := C.ef_vi_receive_fill_level(&dev.vi); level <= dev.refillLevel; {
		dev.refillRxRing()
	}

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
		if err := try(C.ef_vi_filter_add(&dev.vi, dev.dh, efviFilter, nil)); err != nil {
			return errors.Wrap(err, "add filter failed")
		}
	}

	pktCh := make(chan *pkt4go.IPv4Packet, defaultPktBufferLen)

	done := sync.WaitGroup{}

	done.Add(1)
	go func() {
		defer func() {
			close(pktCh)

			done.Done()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// TODO
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
