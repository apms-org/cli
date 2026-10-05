//go:build unix && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package tty

// tcflushInput is not available here; flushInput falls back to draining.
func tcflushInput(fd int) error { return nil }
