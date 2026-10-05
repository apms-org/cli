package tty

import (
	"os"
	"syscall"
)

func handleSignal(ch <-chan os.Signal) {
	sig := <-ch
	Restore()
	code := 1
	if s, ok := sig.(syscall.Signal); ok {
		code = 128 + int(s)
	}
	osExit(code)
}
