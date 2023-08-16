package socket

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/frozenpine/pkt4go"
)

const defaultBufferLen = 4096

func ParseBindInterface(bind string) (iface *net.Interface) {
	if bind == "" {
		return
	}

	localInterfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Find local interface failed: %+v", err)
		return
	}

	lsnrAddr := net.ParseIP(bind)
FIND:
	for _, inter := range localInterfaces {
		if lsnrAddr == nil {
			if inter.Name == bind {
				iface = &inter
				break FIND
			}
		} else {
			addrs, err := inter.Addrs()

			if err != nil {
				continue
			}

			for _, addr := range addrs {
				if strings.Split(addr.String(), "/")[0] == lsnrAddr.String() {
					iface = &inter
					break FIND
				}
			}
		}
	}

	if iface != nil {
		log.Printf("Bind interface[%s] found: %s\n", iface.Name, iface.HardwareAddr.String())
	}

	return
}

// ServeMultiCast join multicast group
func ServeMultiCast(ctx context.Context, listen, bind string, buffSize int, handler pkt4go.DataHandler) error {
	if handler == nil {
		return errors.New("data handler can not be nil")
	}

	listenAddr, err := NewMultiGroupAddr(listen)
	if err != nil {
		return err
	}

	bindInt := ParseBindInterface(bind)
	if bindInt == nil {
		return fmt.Errorf("bind interface[%s] not found", bind)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	lsnr, err := net.ListenMulticastUDP("udp", bindInt, &listenAddr.UDPAddr)
	if err != nil {
		return err
	}

	if buffSize < defaultBufferLen {
		buffSize = defaultBufferLen
	}

	if err := lsnr.SetReadBuffer(buffSize); err != nil {
		return err
	}

	log.Printf("Joined multicast group: %s\n", listenAddr.String())

	buffer := make([]byte, buffSize)

	defer lsnr.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, src, err := lsnr.ReadFromUDP(buffer)
			ts := time.Now()

			if err != nil {
				return err
			}

			session := pkt4go.Session{
				Protocol: pkt4go.UDP,
				SrcAddr:  src.IP,
				SrcPort:  uint16(src.Port),
				DstAddr:  listenAddr.IP,
				DstPort:  uint16(listenAddr.Port),
			}

			if _, err := handler(&session, ts, buffer[:n]); err != nil {
				if e, ok := err.(HandlerError); !ok || !e.IsRecoverable() {
					return err
				}

				log.Println(err)
			}
		}
	}
}
