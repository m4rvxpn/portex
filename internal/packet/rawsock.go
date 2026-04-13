// Package packet implements raw socket I/O, frame builders, libpcap capture,
// and all supported nmap-equivalent scan types.
package packet

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&v))
	return uint16(b[0])<<8 | uint16(b[1])
}

// RawSocket is an AF_PACKET/SOCK_RAW socket for sending raw Ethernet frames.
type RawSocket struct {
	fd    int
	iface string
	ifIdx int
}

// OpenRaw opens an AF_PACKET raw socket bound to the named interface.
// Requires CAP_NET_RAW.
func OpenRaw(iface string) (*RawSocket, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("interface %q not found: %w", iface, err)
	}

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET: %w", err)
	}

	return &RawSocket{fd: fd, iface: iface, ifIdx: ifi.Index}, nil
}

// Write sends a raw Ethernet frame.
func (r *RawSocket) Write(frame []byte) (int, error) {
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  r.ifIdx,
	}
	if err := unix.Sendto(r.fd, frame, 0, sa); err != nil {
		return 0, fmt.Errorf("sendto: %w", err)
	}
	return len(frame), nil
}

// Close closes the socket.
func (r *RawSocket) Close() error {
	return unix.Close(r.fd)
}
