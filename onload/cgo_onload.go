//go:build linux

package onload

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -L./libs -lonload

#include <stdint.h>
#include <stdlib.h>
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

static inline u_int16_t get_ef_event_type(ef_event evt)
{
    return EF_EVENT_TYPE(evt);
}

*/
import "C"
import (
	"context"
	"sync"
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
	defaultFlags        C.enum_ef_vi_flags = C.EF_VI_RX_PACKED_STREAM | C.EF_VI_RX_PS_BUF_SIZE_64K | C.EF_VI_RX_TIMESTAMPS
	defaultHugePageSize int64              = 2 * 1024 * 1024
	defaultPktBufferLen                    = 100
	maxEvents                              = 16
)

var (
	flags        C.enum_ef_vi_flags = defaultFlags
	hugePageSize int64              = defaultHugePageSize
)

type Device struct {
	dh     C.ef_driver_handle
	pd     C.struct_ef_pd
	vi     C.struct_ef_vi
	psp    C.ef_packed_stream_params
	memreg C.struct_ef_memreg
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

	return &dev, nil
}

func createFilter(input string) *C.ef_filter_spec {
	if input == "" {
		return nil
	}

	var filter C.ef_filter_spec

	return &filter
}

// func getEventType(evt C.ef_event) EFEventType {
// 	evtType := (EFEventType(evt[0]) << 8)
// 	evtType |= EFEventType(evt[1])

// 	return evtType
// }

func StartCapture(ctx context.Context, dev *Device, filter string, fn pkt4go.DataHandler) error {
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

	done := sync.WaitGroup{}

	done.Add(1)
	go func() {
		defer func() {
			close(pktCh)

			done.Done()
		}()

		events := [maxEvents]C.ef_event{}

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// TODO: packet handler
				evtCount := int(C.get_ef_event_poll(&dev.vi, (*C.ef_event)(unsafe.Pointer(&events[0])), maxEvents))

				for idx := 0; idx < evtCount; idx++ {
					switch EFEventType(C.get_ef_event_type(events[idx])) {
					case EF_EVENT_TYPE_RX_PACKED_STREAM:
					default:
					}
				}
			}
		}
	}()

	done.Wait()

	return nil
}
