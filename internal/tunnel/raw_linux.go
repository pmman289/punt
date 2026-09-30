//go:build linux

package tunnel

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"
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
	s := &rawSocket{fd: fd}
	// Only Punt's ICMP Type 3/Code 3 packets should reach user space. The
	// parser still validates every field, so filter failure is non-fatal.
	_ = s.SetPeerFilter(nil)
	setSocketBuffers(fd, defaultSocketBuffer)
	return s, nil
}

// SetPeerFilter atomically installs a classic BPF filter for ICMP port
// unreachable packets, optionally constrained to an outer source IPv4 address.
func (s *rawSocket) SetPeerFilter(peer net.IP) error {
	const (
		ldAbsW = syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS
		ldIndB = syscall.BPF_LD | syscall.BPF_B | syscall.BPF_IND
		ldxMsh = syscall.BPF_LDX | syscall.BPF_B | syscall.BPF_MSH
		jeq    = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
		ret    = syscall.BPF_RET | syscall.BPF_K
	)
	program := []syscall.SockFilter{
		{Code: ldxMsh, K: 0},
		{Code: ldIndB, K: 0},
		{Code: jeq, K: 3, Jt: 0, Jf: 3},
		{Code: ldIndB, K: 1},
		{Code: jeq, K: 3, Jt: 0, Jf: 1},
		{Code: ret, K: 0x0000ffff},
		{Code: ret, K: 0},
	}
	if peer4 := peer.To4(); peer4 != nil {
		program = []syscall.SockFilter{
			{Code: ldAbsW, K: 12},
			{Code: jeq, K: binary.BigEndian.Uint32(peer4), Jt: 0, Jf: 6},
			{Code: ldxMsh, K: 0},
			{Code: ldIndB, K: 0},
			{Code: jeq, K: 3, Jt: 0, Jf: 3},
			{Code: ldIndB, K: 1},
			{Code: jeq, K: 3, Jt: 0, Jf: 1},
			{Code: ret, K: 0x0000ffff},
			{Code: ret, K: 0},
		}
	}
	fprog := syscall.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s.fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER), uintptr(unsafe.Pointer(&fprog)), unsafe.Sizeof(fprog), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (s *rawSocket) Send(packet []byte, destination Tuple) error {
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], destination.IP.To4())
	return syscall.Sendto(s.fd, packet, 0, &addr)
}

func (s *rawSocket) Receive(buffer []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buffer, 0)
	return n, err
}

func (s *rawSocket) Close() error { return syscall.Close(s.fd) }
