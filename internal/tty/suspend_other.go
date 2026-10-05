//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package tty

func suspendFuncs(con console) (func() bool, func()) { return nil, nil }
