//go:build linux

package tunnel

import (
	"errors"
	"syscall"
)

type rawSocket struct{ fd int }

func openRawSocket() (*rawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, errors.New("opening raw ICMP socket requires CAP_NET_RAW (run as root or grant cap_net_raw=ep)")
		}
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	// Linux doubles this value and caps it by the host policy. Requesting a
	// larger buffer lets a paced receiver absorb brief scheduling delays without
	// requiring a global sysctl change.
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
	return &rawSocket{fd: fd}, nil
}

func (s *rawSocket) Send(packet []byte, destination Tuple) error {
	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], destination.IP.To4())
	return syscall.Sendto(s.fd, packet, 0, addr)
}

func (s *rawSocket) Receive(buffer []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buffer, 0)
	return n, err
}

func (s *rawSocket) Close() error { return syscall.Close(s.fd) }
