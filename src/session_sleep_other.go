//go:build !darwin && !linux

package apm

func sleepMark() (int64, bool) { return 0, false }

func sleptSince(mark int64) bool { return false }
