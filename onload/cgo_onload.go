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
*/
import "C"
import (
	"context"
	"sync"

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

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// TODO: packet handler
			}
		}
	}()

	done.Wait()

	return nil
}
