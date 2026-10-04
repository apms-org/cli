//go:build linux

package apm

import "golang.org/x/sys/unix"

// sleepMark is how many seconds the computer has spent suspended since boot:
// CLOCK_BOOTTIME counts suspend and CLOCK_MONOTONIC does not.
func sleepMark() (int64, bool) {
	var boot, mono unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil || unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono) != nil {
		return 0, false
	}
	return boot.Sec - mono.Sec, true
}

func sleptSince(mark int64) bool {
	now, ok := sleepMark()
	return ok && now-mark > 2
}
