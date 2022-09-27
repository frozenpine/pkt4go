//go:build linux

package onload

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -L./libs -lonload

#include <stdint.h>
#include <stdlib.h>

#include <etherfabric/base.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>
*/
import "C"
import "github.com/pkg/errors"

// func GetVersion() string {
// 	return C.GoString(ef_vi_version_str())
// }

// func GetInterfaceVersion() string {
// 	return C.GoString(ef_vi_driver_interface_str())
// }

type Device struct {
	dh C.ef_driver_handle
	pd C.struct_ef_pd
	vi C.struct_ef_vi
}

func CreateHandler(src string) (*Device, error) {
	if src == "" {
		return nil, errors.New("device can not be empty")
	}

	dev := Device{}

	if C.ef_driver_open(&dev.dh) != 0 {
		return nil, errors.New("driver open failed")
	}

	// C.ef_pd_alloc_by_name(&dev.protectDomain, dev.handler, C.CString(src), C.EF_PD_RX_PACKED_STREAM)

	return &dev, nil
}
