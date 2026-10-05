//go:build linux

package tty

import "golang.org/x/sys/unix"

func tcflushInput(fd int) error {
	return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
}
