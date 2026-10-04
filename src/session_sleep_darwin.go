//go:build darwin

package apm

import "golang.org/x/sys/unix"

// sleepMark is the time of the last wake from sleep. It changes every time the
// Mac wakes, so a session that remembers it can tell the Mac slept since.
func sleepMark() (int64, bool) {
	tv, err := unix.SysctlTimeval("kern.waketime")
	if err != nil {
		return 0, false
	}
	return tv.Sec, true
}

func sleptSince(mark int64) bool {
	now, ok := sleepMark()
	return ok && now != mark
}
