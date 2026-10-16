//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package miner

import (
	"os"
	"syscall"
)

// Unix O_NONBLOCK prevents an opening race with a FIFO from blocking before
// the opened file can be independently checked with Fstat.
func openInputNoBlock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
