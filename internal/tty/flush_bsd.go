//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package tty

import "golang.org/x/sys/unix"

// tcflush(fd, TCIFLUSH) is ioctl(fd, TIOCFLUSH, &FREAD) on the BSDs.
func tcflushInput(fd int) error {
	const fread = 1
	return unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, fread)
}
