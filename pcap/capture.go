package pcap

import (
	"context"
	"io"
	"log"
	"net"
	"regexp"
	"time"

	"github.com/frozenpine/pkt4go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	libpcap "github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

const (
	defaultTCPBufferLen = 1024 * 1024
)

var (
	dataSourcePattern = regexp.MustCompile(`^(?P<proto>pcap|file)://(?P<source>.*)$`)
)

func CreateHandler(dataSrc string) (handle *libpcap.Handle, err error) {
	srcMatch := dataSourcePattern.FindStringSubmatch(dataSrc)
	if srcMatch == nil {
		return nil, errors.New("invalid data source: " + dataSrc)
	}

	var proto, source string

	for idx, name := range dataSourcePattern.SubexpNames() {
		switch name {
		case "proto":
			proto = srcMatch[idx]
		case "source":
			source = srcMatch[idx]
		}
	}

	// Find inteface name if source is an IP address
	if ip, err := net.ResolveIPAddr("ip", source); err == nil {
		ifaceList, err := libpcap.FindAllDevs()
		if err != nil {
			return nil, errors.WithStack(err)
		}

	FIND_IFACE:
		for _, iface := range ifaceList {
			for _, addr := range iface.Addresses {
				if addr.IP.Equal(ip.IP) {
					source = iface.Name
					break FIND_IFACE
				}
			}
		}
	}

	switch proto {
	case "pcap":
		if handle, err = libpcap.OpenLive(source, 65535, true, time.Hour); err != nil {
			return nil, errors.WithStack(err)
		}
	case "file":
		if handle, err = libpcap.OpenOffline(source); err != nil {
			return nil, errors.WithStack(err)
		}
	default:
		return nil, errors.New("unknown pcap protocol: " + proto)
	}

	return
}

func StartCapture(ctx context.Context, handler *libpcap.Handle, filter string, fn pkt4go.DataHandler) (err error) {
	if err := handler.SetBPFFilter(filter); err != nil {
		return errors.WithStack(err)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	packets := gopacket.NewPacketSource(handler, handler.LinkType()).Packets()

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkg := <-packets:
			if pkg == nil {
				return nil
			}

			if fn == nil {
				continue
			}

			ip := pkg.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if ip == nil {
				log.Printf("%+v", errors.New("captured packet is not a valid IPv4 packet"))
				continue
			}

			var (
				session *pkt4go.Session
				buffer  []byte
			)

			switch ip.NextLayerType() {
			case layers.LayerTypeTCP:
				tcp, _ := pkg.Layer(layers.LayerTypeTCP).(*layers.TCP)

				if len(tcp.Payload) <= 0 {
					continue
				}

				session = &pkt4go.Session{
					Protocol: pkt4go.TCP.String(),
					SrcAddr:  ip.SrcIP,
					SrcPort:  uint16(tcp.SrcPort),
					DstAddr:  ip.DstIP,
					DstPort:  uint16(tcp.DstPort),
				}

				buffer = tcp.Payload
			case layers.LayerTypeUDP:
				udp, _ := pkg.Layer(layers.LayerTypeUDP).(*layers.UDP)

				if len(udp.Payload) <= 0 {
					continue
				}

				session = &pkt4go.Session{
					Protocol: pkt4go.UDP.String(),
					SrcAddr:  ip.SrcIP,
					SrcPort:  uint16(udp.SrcPort),
					DstAddr:  ip.DstIP,
					DstPort:  uint16(udp.DstPort),
				}

				buffer = udp.Payload
			default:
				log.Println("unsupported Transport Layer: " + ip.NextLayerType().String())
			}

			_, err = fn(session, pkg.Metadata().Timestamp, buffer)

			if err != nil {
				if err == io.EOF {
					return nil
				}

				log.Printf("[%s] %s data handler failed: %v", pkg.Metadata().Timestamp, session, err)
			}
		}
	}
}
