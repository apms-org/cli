//go:build !unix && !windows

package tty

import (
	"os"
	"os/signal"
)

func openConsole() (console, bool) { return nil, false }

func installSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go handleSignal(ch)
}
