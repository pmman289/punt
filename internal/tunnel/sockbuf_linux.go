//go:build linux

package tunnel

import (
	"net"
	"syscall"
)

const defaultSocketBuffer = 4 << 20

func tuneUDPBuffers(conn *net.UDPConn, size int) int {
	if conn == nil || size <= 0 {
		return 0
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	effective := 0
	_ = raw.Control(func(fd uintptr) { effective = setSocketBuffers(int(fd), size) })
	return effective
}

func setSocketBuffers(fd, size int) int {
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, size) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
	}
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, size) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	}
	got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return 0
	}
	return got / 2
}
