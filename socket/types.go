package socket

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	tcpPrefix = "tcp://"
	udpPrefix = "udp://"
)

// TCPFront tcp address
type TCPFront struct {
	net.TCPAddr
}

// UnmarshalText unmarshal tcp address from text
func (addr *TCPFront) UnmarshalText(text []byte) error {
	str := strings.ToLower(string(text))

	if !strings.HasPrefix(str, tcpPrefix) {
		return ErrTCPPrefix
	}

	str = strings.TrimPrefix(str, tcpPrefix)

	resolve, err := net.ResolveTCPAddr("tcp", str)
	if err != nil {
		return err
	}

	addr.TCPAddr = *resolve

	return nil
}

// MarshalText marshal tcp address to text
func (addr TCPFront) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

func (addr *TCPFront) String() string {
	buff := bytes.NewBufferString(tcpPrefix)
	buff.WriteString(addr.TCPAddr.String())
	return buff.String()
}

func makeFrontAddr(prefix, addr string, port int) string {
	buff := bytes.NewBufferString(prefix)
	buff.WriteString(addr)
	buff.WriteRune(':')
	buff.WriteString(strconv.Itoa(port))

	return buff.String()
}

// NewTCPFront create new tcp front
func NewTCPFront(addr string, port int) (*TCPFront, error) {
	front := TCPFront{}

	if err := front.UnmarshalText(
		[]byte(makeFrontAddr(tcpPrefix, addr, port)),
	); err != nil {
		return nil, err
	}

	return &front, nil
}

// UDPFront udp address
type UDPFront struct {
	net.UDPAddr
}

// UnmarshalText unmarshal udp address from text
func (addr *UDPFront) UnmarshalText(text []byte) error {
	str := strings.ToLower(string(text))

	if !strings.HasPrefix(str, udpPrefix) {
		return ErrUDPPrefix
	}

	str = strings.TrimPrefix(str, udpPrefix)

	resolve, err := net.ResolveUDPAddr("udp", str)
	if err != nil {
		return err
	}

	addr.UDPAddr = *resolve

	return nil
}

// MarshalText marshal udp address to text
func (addr UDPFront) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

func (addr *UDPFront) String() string {
	buff := bytes.NewBufferString(udpPrefix)
	buff.WriteString(addr.UDPAddr.String())
	return buff.String()
}

// NewUDPFront create new udp front
func NewUDPFront(addr string, port int) (*UDPFront, error) {
	front := UDPFront{}

	if err := front.UnmarshalText(
		[]byte(makeFrontAddr(udpPrefix, addr, port)),
	); err != nil {
		return nil, err
	}

	return &front, nil
}

// MultiGroupAddr multigroup address
type MultiGroupAddr struct {
	net.UDPAddr
}

// UnmarshalText unmarshal from toml text
func (addr *MultiGroupAddr) UnmarshalText(text []byte) error {
	value := string(text)
	resolve, err := net.ResolveUDPAddr("udp", value)
	if err != nil {
		return err
	}

	if !resolve.IP.IsMulticast() {
		return fmt.Errorf("%w: %s", ErrMulticastAddr, value)
	}

	addr.UDPAddr = *resolve

	return nil
}

// MarshalText marshal multicast group address to text
func (addr MultiGroupAddr) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

// NewMultiGroupAddr create MultiGroupAddr from string
func NewMultiGroupAddr(v string) (*MultiGroupAddr, error) {
	addr := MultiGroupAddr{}
	err := addr.UnmarshalText([]byte(v))
	if err != nil {
		return nil, err
	}

	return &addr, nil
}
