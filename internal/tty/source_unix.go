//go:build unix

package tty

import (
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// unixConsole reads a terminal fd with select(2) + read(2). select is used
// rather than poll(2) because macOS poll does not support devices, and
// rather than kqueue, which returns immediately for /dev/tty on macOS.
type unixConsole struct {
	fd int
}

func openConsole() (console, bool) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, false
	}
	return &unixConsole{fd: fd}, false
}

func (c *unixConsole) Read(p []byte, timeout time.Duration) (int, error) {
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		var tv *unix.Timeval
		if timeout >= 0 {
			rem := time.Until(deadline)
			if rem < 0 {
				rem = 0
			}
			t := unix.NsecToTimeval(rem.Nanoseconds())
			tv = &t
		}
		var fds unix.FdSet
		fds.Zero()
		fds.Set(c.fd)
		n, err := unix.Select(c.fd+1, &fds, nil, nil, tv)
		if err == unix.EINTR {
			continue // recompute the remaining time and wait again
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, nil // timeout
		}
		m, err := unix.Read(c.fd, p)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return 0, err
		}
		if m == 0 {
			return 0, io.EOF
		}
		return m, nil
	}
}

func (c *unixConsole) makeRaw() (func() error, error) {
	st, err := term.MakeRaw(c.fd)
	if err != nil {
		return nil, err
	}
	return func() error { return term.Restore(c.fd, st) }, nil
}

func (c *unixConsole) flushInput() error {
	err := tcflushInput(c.fd)
	// Drain whatever is still readable without blocking.
	var b [512]byte
	for i := 0; i < 64; i++ {
		n, rerr := c.Read(b[:], 0)
		if n == 0 || rerr != nil {
			break
		}
	}
	return err
}

func (c *unixConsole) enableOutputVT() (func(), bool) {
	return func() {}, os.Getenv("TERM") != "dumb"
}

func installSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go handleSignal(ch)
}
