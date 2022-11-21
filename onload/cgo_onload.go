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
#include <poll.h>

#include <etherfabric/base.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>
#include <etherfabric/memreg.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

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

type Mode uint8

const (
	EvqWait Mode = iota
	FDWait
	LowLatency
	BatchPoll
)

const (
	defaultFlags        C.enum_ef_vi_flags = C.EF_VI_FLAGS_DEFAULT | C.EF_VI_RX_TIMESTAMPS
	defaultHugePageSize int64              = 2 * 1024 * 1024

	EV_POLL_BATCH_SIZE      = 16
	REFILL_BATCH_SIZE       = 16
	PKT_BUF_SIZE            = 2048
	EF_VI_RECEIVE_BATCH int = int(C.EF_VI_RECEIVE_BATCH)

	defaultRunMode = EvqWait

	defaultPktBufferLen = 100
	defaultTCPBufferLen = 1024 * 1024
)

var (
	flags        C.enum_ef_vi_flags = defaultFlags
	hugePageSize                    = defaultHugePageSize
	runMode                         = defaultRunMode

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
	pd unsafe.Pointer

	/* virtual interface (rxq + txq) */
	vi                        unsafe.Pointer
	rxPrefixLen, pktLenOffset C.int
	refillLevel, refillMin    C.int
	batchLoops                int

	/* registered memory for DMA */
	nBufs   C.int
	evqSize C.int
	pktBufs unsafe.Pointer
	memreg  unsafe.Pointer

	/* pool of free packet buffers (LIFO to minimise working set) */
	freePktBufs  *C.pkt_buf_t
	nFreePktBufs int

	/* statistics */
	rxPkts  uint64
	rxBytes uint64

	once    sync.Once
	isIOMMU bool
}

func (dev *Device) closeDH() {
	C.ef_driver_close(dev.dh)
	dev.dh = 0
}

func (dev *Device) freePD() {
	C.ef_pd_free((*C.struct_ef_pd)(dev.pd), dev.dh)
	dev.pd = nil
}

func (dev *Device) freeVI() {
	C.ef_vi_free((*C.struct_ef_vi)(dev.vi), dev.dh)
	dev.vi = nil
}

func (dev *Device) Release() {
	dev.once.Do(func() {
		dev.freeVI()

		dev.freePD()

		dev.closeDH()
	})
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

func (dev *Device) handleRx(pktBufIdx, len int, pktCh chan<- *pkt4go.IPv4Packet) error {
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
		(*C.struct_ef_vi)(dev.vi), dmaPtr, &hwTS, &tsFlags,
	)); err != nil {
		return err
	}

	ts := time.Unix(int64(hwTS.tv_sec), int64(hwTS.tv_nsec))
	// payload := C.GoBytes(pktBuf.rx_ptr, C.int(len))
	payload := *(*[]byte)(unsafe.Pointer(
		&reflect.SliceHeader{
			Data: uintptr(pktBuf.rx_ptr),
			Len:  len,
			Cap:  len,
		},
	))

	frm := pkt4go.CreateEtherFrame(payload, ts)

	frm.DelegateRelease(func() {
		dev.releasePktBuf(pktBuf)
	})

	if err := frm.Unpack(frm.Buffer); err != nil {
		frm.Release()
		return err
	}

	if frm.Type != pkt4go.ProtoIP {
		log.Printf(
			"%s received non-IP ether frame[%#04x]: %s -> %s",
			frm.Timestamp, uint16(frm.Type), frm.SrcHost, frm.DstHost,
		)
		frm.Release()
	} else {
		pkt := pkt4go.CreateIPv4Packet(frm)

		if err := pkt.Unpack(frm.GetPayload()); err != nil {
			pkt.Release()
			return err
		}

		pktCh <- pkt
	}

	dev.rxPkts += 1
	dev.rxBytes += uint64(len)

	return nil
}

func (dev *Device) handleBatchRx(pktBufIdx int, pktCh chan<- *pkt4go.IPv4Packet) error {
	pktBuf, err := dev.pktBufFromID(pktBufIdx)
	if err != nil {
		return err
	}

	dmaPtr := uintptr(unsafe.Pointer(pktBuf)) + uintptr(C.RX_DMA_OFF)

	dataLen := *(*uint16)(unsafe.Pointer(dmaPtr + uintptr(dev.pktLenOffset)))

	return dev.handleRx(pktBufIdx, int(dataLen), pktCh)
}

func (dev *Device) handleRxDiscard(pktBufIdx, len int, typ EFRxDiscardType) error {
	if verbose {
		log.Printf("Packet discarded due to: %#04x", uint16(typ))
	}

	pktBuf, err := dev.pktBufFromID(pktBufIdx)
	if err != nil {
		return err
	}

	dev.releasePktBuf(pktBuf)

	return nil
}

func (dev *Device) refillRxRing() bool {
	if C.ef_vi_receive_fill_level((*C.struct_ef_vi)(dev.vi)) > dev.refillLevel ||
		dev.nFreePktBufs < REFILL_BATCH_SIZE {
		return false
	}

	var pktBuf *C.pkt_buf_t

	for next := true; next; next = C.ef_vi_receive_fill_level((*C.struct_ef_vi)(dev.vi)) < dev.refillMin && dev.nFreePktBufs >= REFILL_BATCH_SIZE {
		for i := 0; i < REFILL_BATCH_SIZE; i++ {
			pktBuf = (*C.pkt_buf_t)(dev.freePktBufs)
			dev.freePktBufs = dev.freePktBufs.next
			dev.nFreePktBufs--
			C.exec_ef_vi_receive_init((*C.struct_ef_vi)(dev.vi), unsafe.Pointer(uintptr(pktBuf.ef_addr+C.RX_DMA_OFF)), pktBuf.id)
		}
	}

	C.exec_ef_vi_receive_push((*C.struct_ef_vi)(dev.vi))

	return true
}

func (dev *Device) pollEvq(pktCh chan<- *pkt4go.IPv4Packet) (int, error) {
	events := [EV_POLL_BATCH_SIZE]C.ef_event{}
	IDs := [EF_VI_RECEIVE_BATCH]C.ef_request_id{}

	eventCount := int(C.exec_ef_event_poll((*C.struct_ef_vi)(dev.vi), (*C.ef_event)(unsafe.Pointer(&events[0])), EV_POLL_BATCH_SIZE))

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

			if err := dev.handleRx(int(dmaIdx), int(nBytes), pktCh); err != nil {
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
			(*C.struct_ef_vi)(dev.vi), evt, (*C.ef_request_id)(unsafe.Pointer(&IDs[0]))),
		)

		for idx := 0; idx < nRx; idx++ {
			dev.handleBatchRx(int(IDs[idx]), pktCh)
		}
	}

	return eventCount, nil
}

func (dev *Device) eventLoopThroughput(ctx context.Context, pktCh chan<- *pkt4go.IPv4Packet) error {
	evtLookAhead := EV_POLL_BATCH_SIZE + 7

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			dev.refillRxRing()

			dev.batchLoops--

			/* Avoid reading entries in the EVQ that are in the same cache line
			 * that the network adapter is writing to.
			 */
			if C.ef_eventq_has_many_events((*C.struct_ef_vi)(dev.vi), C.int(evtLookAhead)) != 0 || dev.batchLoops == 0 {
				if _, err := dev.pollEvq(pktCh); err != nil {
					return err
				}

				dev.batchLoops = 100
			}
		}
	}
}

func (dev *Device) eventLoopLowLatency(ctx context.Context, pktCh chan<- *pkt4go.IPv4Packet) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			dev.refillRxRing()

			if _, err := dev.pollEvq(pktCh); err != nil {
				return err
			}
		}
	}
}

func (dev *Device) eventLoopBlocking(ctx context.Context, pktCh chan<- *pkt4go.IPv4Packet) error {
	var refilled bool

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			refilled = dev.refillRxRing()

			evtCount, err := dev.pollEvq(pktCh)

			if err != nil {
				return err
			}

			if !refilled && evtCount == 0 {
				if err := try(C.ef_eventq_wait(
					(*C.struct_ef_vi)(dev.vi), dev.dh,
					C.ef_eventq_current((*C.struct_ef_vi)(dev.vi)), nil,
				)); err != nil {
					return err
				}
			}
		}
	}
}

func (dev *Device) eventLoopBlockingPoll(ctx context.Context, pktCh chan<- *pkt4go.IPv4Packet) error {
	pollFD := C.struct_pollfd{fd: dev.dh, events: C.POLLIN, revents: 0}

	if err := try(C.ef_vi_prime(
		(*C.struct_ef_vi)(dev.vi),
		dev.dh, C.ef_eventq_current((*C.struct_ef_vi)(dev.vi)))); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if err := try(C.poll(&pollFD, 1, -1)); err != nil {
				return err
			}

			if pollFD.events&C.POLLIN == 0 {
				continue
			}

			for {
				refilled := dev.refillRxRing()

				if evtCount, err := dev.pollEvq(pktCh); err != nil {
					return err
				} else if evtCount == 0 && !refilled {
					break
				}
			}

			if err := try(C.ef_vi_prime(
				(*C.struct_ef_vi)(dev.vi), dev.dh,
				C.ef_eventq_current((*C.struct_ef_vi)(dev.vi)),
			)); err != nil {
				return err
			}
		}
	}
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

// TODO: ef_vi in IOMMU
func CreateHandler(iface string, isIOMMU bool) (*Device, error) {
	if iface == "" {
		return nil, errors.New("device can not be empty")
	}

	dev := Device{
		pd:      C.malloc(C.sizeof_struct_ef_pd),
		vi:      C.malloc(C.sizeof_struct_ef_vi),
		memreg:  C.malloc(C.sizeof_struct_ef_memreg),
		isIOMMU: isIOMMU,
	}

	if err := try(C.ef_driver_open(&dev.dh)); err != nil {
		return nil, errors.Wrap(err, "driver open failed")
	}

	// pdFlag := C.EF_PD_DEFAULT

	// if dev.isIOMMU {
	// 	pdFlag = C.EF_PD_VF | C.EF_PD_VPORT
	// }

	if err := try(C.ef_pd_alloc_by_name(
		(*C.struct_ef_pd)(dev.pd),
		dev.dh,
		C.CString(iface),
		C.EF_PD_DEFAULT,
	)); err != nil {
		dev.closeDH()

		return nil, errors.Wrap(err, "alloc protect domain failed")
	}

	if err := try(C.ef_vi_alloc_from_pd(
		(*C.struct_ef_vi)(dev.vi), dev.dh,
		(*C.struct_ef_pd)(dev.pd), dev.dh,
		-1, -1, 0, nil, -1,
		flags,
	)); err != nil {
		dev.freePD()
		dev.closeDH()

		return nil, errors.Wrap(err, "alloc virtual interface failed")
	}

	dev.rxPrefixLen = C.ef_vi_receive_prefix_len((*C.struct_ef_vi)(dev.vi))

	var layoutPtr uintptr
	var len C.int
	if err := try(C.ef_vi_receive_query_layout(
		(*C.struct_ef_vi)(dev.vi),
		(**C.ef_vi_layout_entry)(unsafe.Pointer(&layoutPtr)),
		(*C.int)(unsafe.Pointer(&len)),
	)); err != nil {
		return nil, errors.Wrap(err, "query layout failed")
	} else {
		layoutLen := int(len)
		layoutSlice := *(*[]C.ef_vi_layout_entry)(
			unsafe.Pointer(&reflect.SliceHeader{
				Data: layoutPtr,
				Len:  layoutLen,
				Cap:  layoutLen,
			}),
		)

		for _, layout := range layoutSlice {
			if layout.evle_type != C.EF_VI_LAYOUT_PACKET_LENGTH {
				continue
			}

			dev.pktLenOffset = layout.evle_offset
		}
	}

	dev.nBufs = C.ef_vi_receive_capacity((*C.struct_ef_vi)(dev.vi)) - C.int(REFILL_BATCH_SIZE)
	dev.evqSize = C.ef_eventq_capacity((*C.struct_ef_vi)(dev.vi))

	if verbose {
		log.Printf(
			"max_fill=%d\nevq_size=%d\nrx_prefix_len=%d",
			dev.nBufs, dev.evqSize, dev.rxPrefixLen,
		)
	}

	allocSize := C.round_up(dev.nBufs*C.int(PKT_BUF_SIZE), C.int(hugePageSize))

	dev.pktBufs = C.mmap(nil, allocSize, C.PROT_READ|C.PROT_WRITE,
		C.MAP_ANONYMOUS|C.MAP_PRIVATE|C.MAP_HUGETLB, -1, 0)
	if dev.pktBufs == C.MAP_FAILED {
		log.Printf("Require mmap failed, are huge pages configured?")

		/* Allocate huge-page-aligned memory to give best chance of allocating
		 * transparent huge-pages.
		 */
		if err := try(C.posix_memalign(&(dev.pktBufs), C.ulong(hugePageSize), C.ulong(allocSize))); err != nil {
			return nil, errors.Wrap(err, "transparent huge-pages align failed")
		}
	}

	for idx := 0; idx < int(dev.nBufs); idx++ {
		buf, _ := dev.pktBufFromID(idx)

		buf.rx_ptr = unsafe.Pointer(
			uintptr(unsafe.Pointer(buf)) + uintptr(C.RX_DMA_OFF) + uintptr(dev.rxPrefixLen),
		)
		buf.id = C.int(idx)

		dev.releasePktBuf(buf)
	}

	if err := try(C.ef_memreg_alloc((*C.struct_ef_memreg)(dev.memreg), dev.dh, (*C.struct_ef_pd)(dev.pd), dev.dh, dev.pktBufs, allocSize)); err != nil {
		return nil, errors.Wrap(err, "memreg alloc failed")
	}

	log.Println("memreg alloc succeed.")

	for idx := 0; idx < int(dev.nBufs); idx++ {
		buf, _ := dev.pktBufFromID(idx)

		buf.ef_addr = C.ef_memreg_dma_addr((*C.struct_ef_memreg)(dev.memreg), C.size_t(idx*PKT_BUF_SIZE))
	}

	dev.refillLevel = dev.nBufs - C.int(REFILL_BATCH_SIZE)
	dev.refillMin = dev.nBufs / 2

	log.Printf("refill level: %d, refill min:%d", dev.refillLevel, dev.refillMin)

	for C.ef_vi_receive_fill_level((*C.struct_ef_vi)(dev.vi)) <= dev.refillLevel {
		dev.refillRxRing()
	}

	log.Println("ef_vi handler created.")

	return &dev, nil
}

func createFilter(input string) *C.ef_filter_spec {
	filter := C.ef_filter_spec{}

	if err := try(C.ef_filter_spec_set_port_sniff(&filter, 1)); err != nil {
		return nil
	}

	if input != "" {
		// TODO: filter parse
	}

	return &filter
}

func StartCapture(ctx context.Context, dev *Device, filter string, fn pkt4go.DataHandler) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	log.Println("Start capture.")

	defer dev.Release()

	if efviFilter := createFilter(filter); dev.isIOMMU && efviFilter != nil {
		if err := try(C.ef_vi_filter_add((*C.struct_ef_vi)(dev.vi), dev.dh, efviFilter, nil)); err != nil {
			return errors.Wrap(err, "add filter failed")
		}
	}

	pktCh := make(chan *pkt4go.IPv4Packet, defaultPktBufferLen)

	var eventLoop func(context.Context, chan<- *pkt4go.IPv4Packet) error

	switch runMode {
	case EvqWait:
		eventLoop = dev.eventLoopBlocking
	case FDWait:
		eventLoop = dev.eventLoopBlockingPoll
	case LowLatency:
		eventLoop = dev.eventLoopLowLatency
	case BatchPoll:
		eventLoop = dev.eventLoopThroughput
	default:
		return errors.New("no valid run mode specified")
	}

	done := sync.WaitGroup{}

	done.Add(1)
	go func() {
		defer func() {
			dev.Release()

			close(pktCh)

			done.Done()
		}()

		err = eventLoop(ctx, pktCh)
	}()

	var (
		segment pkt4go.PktData
		session *pkt4go.Session
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

					goto NEXT
				}

				segment = tcp
				session = tcp.Flow()
			case pkt4go.UDP:
				udp := pkt4go.CreateUDPSegment(pkt)

				if err = udp.Unpack(pkt.GetPayload()); err != nil {
					log.Printf("unpack udp header failed: %v", err)

					goto NEXT
				}

				segment = udp
				session = udp.Flow()
			default:
				log.Printf(
					"HwTS[%s] unsuppored transport[%#02x]: %v",
					pkt.GetTimestamp(), uint8(pkt.Protocol),
					pkt.GetPayload(),
				)

				goto NEXT
			}

			_, err = fn(session, segment.GetTimestamp(), segment.GetPayload())

			if err != nil {
				defer func() {
					dev.Release()
				}()

				if segment != nil {
					segment.Release()
				} else {
					pkt.Release()
				}

				if err == io.EOF {
					return nil
				}

				log.Printf("payload handler error: %v", err)
				return
			}

		NEXT:
			if segment != nil {
				segment.Release()
			} else {
				pkt.Release()
			}
		}
	}

	done.Wait()

	return
}
