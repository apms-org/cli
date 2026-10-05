//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package tty

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// suspendFuncs implements Ctrl+Z like a cooked-mode terminal would: stop
// the process group with SIGTSTP and continue after SIGCONT. It is only
// allowed when we are the terminal's foreground process group; otherwise
// the stop could never be undone by the shell.
func suspendFuncs(con console) (func() bool, func()) {
	uc, ok := con.(*unixConsole)
	if !ok {
		return nil, nil
	}
	can := func() bool {
		pgrp, err := unix.IoctlGetInt(uc.fd, unix.TIOCGPGRP)
		return err == nil && pgrp == unix.Getpgrp()
	}
	suspend := func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGCONT)
		defer signal.Stop(ch)
		if err := syscall.Kill(0, syscall.SIGTSTP); err != nil {
			return
		}
		// The kernel silently discards SIGTSTP for an orphaned process
		// group (e.g. `ssh -t host pm ...`, or any session leader without
		// a job-control shell); SIGCONT would then never come. A stop takes
		// effect at once, so if we are still running after a short wait we
		// were not stopped. If we were, the timer has long expired by the
		// time we continue, and either case proceeds.
		select {
		case <-ch:
		case <-time.After(250 * time.Millisecond):
		}
	}
	return can, suspend
}
