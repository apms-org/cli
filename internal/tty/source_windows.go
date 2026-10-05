//go:build windows

package tty

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/erikgeiser/coninput"
	"github.com/mattn/go-isatty"
	"golang.org/x/sys/windows"
)

// winConsole reads INPUT_RECORDs from the console input handle.
//
// os.Stdin.Read is not used: Go's console reader keeps UTF-8 leftovers in
// a private buffer (invisible to WaitForSingleObject, which breaks the
// Esc timeout) and turns a 0x1A byte into io.EOF.
type winConsole struct {
	in   windows.Handle
	vt   bool   // ENABLE_VIRTUAL_TERMINAL_INPUT is on
	pend []byte // encoded bytes not yet returned
	hi   uint16 // pending high surrogate
}

func openConsole() (console, bool) {
	fd := os.Stdin.Fd()
	h := windows.Handle(fd)
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		return &winConsole{in: h}, false
	}
	// mintty (Git Bash, MSYS2, Cygwin) without ConPTY: stdin is a named
	// pipe. Keys cannot be decoded and echo cannot be turned off.
	return nil, isatty.IsCygwinTerminal(fd)
}

func (c *winConsole) makeRaw() (func() error, error) {
	var orig uint32
	if err := windows.GetConsoleMode(c.in, &orig); err != nil {
		return nil, err
	}
	raw := orig &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT |
		windows.ENABLE_LINE_INPUT | windows.ENABLE_MOUSE_INPUT | windows.ENABLE_WINDOW_INPUT)
	if err := windows.SetConsoleMode(c.in, raw|windows.ENABLE_VIRTUAL_TERMINAL_INPUT); err == nil {
		c.vt = true
	} else if err := windows.SetConsoleMode(c.in, raw&^windows.ENABLE_VIRTUAL_TERMINAL_INPUT); err == nil {
		// Consoles without VT input (Windows 7/8.1, some legacy-console
		// setups) reject the flag with ERROR_INVALID_PARAMETER.
		c.vt = false
	} else {
		return nil, err
	}
	c.hi = 0
	return func() error { return windows.SetConsoleMode(c.in, orig) }, nil
}

func (c *winConsole) Read(p []byte, timeout time.Duration) (int, error) {
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	expired := func() bool { return timeout >= 0 && !time.Now().Before(deadline) }
	for {
		if len(c.pend) > 0 {
			n := copy(p, c.pend)
			c.pend = c.pend[n:]
			if len(c.pend) == 0 {
				c.pend = nil
			}
			return n, nil
		}
		ms := uint32(windows.INFINITE)
		if timeout >= 0 {
			rem := time.Until(deadline)
			if rem < 0 {
				rem = 0
			}
			ms = uint32((rem + time.Millisecond - 1) / time.Millisecond)
		}
		ev, err := windows.WaitForSingleObject(c.in, ms)
		if err != nil {
			return 0, err
		}
		switch ev {
		case uint32(windows.WAIT_TIMEOUT):
			return 0, nil
		case windows.WAIT_OBJECT_0:
		default:
			return 0, fmt.Errorf("tty: WaitForSingleObject returned %#x", ev)
		}
		n, err := coninput.GetNumberOfConsoleInputEvents(c.in)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			// Spurious wake-up (seen on Windows Terminal).
			if expired() {
				return 0, nil
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if n > 128 {
			n = 128
		}
		recs, err := coninput.ReadNConsoleInputs(c.in, n)
		if err != nil {
			return 0, err
		}
		c.pend = c.encode(c.pend, recs)
		// Records that produce no bytes (key-up, focus, menu, mouse,
		// resize) mean: keep waiting with the remaining time.
		if len(c.pend) == 0 && expired() {
			return 0, nil
		}
	}
}

func (c *winConsole) encode(dst []byte, recs []coninput.InputRecord) []byte {
	for _, rec := range recs {
		if rec.EventType != coninput.KeyEventType {
			continue
		}
		ke, ok := rec.Unwrap().(coninput.KeyEventRecord)
		if !ok {
			continue
		}
		if !ke.KeyDown {
			// Alt+Numpad composition delivers the character on Alt key-up.
			if ke.VirtualKeyCode != coninput.VK_MENU || ke.Char == 0 {
				continue
			}
		}
		var seq []byte
		if ke.Char != 0 {
			r := rune(uint16(ke.Char))
			if utf16.IsSurrogate(r) {
				if r < 0xdc00 { // high surrogate: wait for the low half
					c.hi = uint16(r)
					continue
				}
				if c.hi == 0 {
					continue // stray low surrogate
				}
				r = utf16.DecodeRune(rune(c.hi), r)
				c.hi = 0
			} else {
				c.hi = 0
			}
			seq = utf8.AppendRune(nil, r)
			if !c.vt && ke.KeyDown {
				cks := ke.ControlKeyState
				shift := cks&coninput.SHIFT_PRESSED != 0
				alt := cks&(coninput.LEFT_ALT_PRESSED|coninput.RIGHT_ALT_PRESSED) != 0
				ctrl := cks&(coninput.LEFT_CTRL_PRESSED|coninput.RIGHT_CTRL_PRESSED) != 0
				switch {
				case r == '\t' && shift:
					seq = []byte("\x1b[Z")
				case alt && !ctrl: // AltGr is reported as Ctrl+Alt
					seq = append([]byte{0x1b}, seq...)
				}
			}
		} else if !c.vt {
			seq = vkSequence(ke.VirtualKeyCode, ke.ControlKeyState)
		}
		if len(seq) == 0 {
			continue
		}
		rep := int(ke.RepeatCount)
		if rep < 1 || !ke.KeyDown {
			rep = 1
		}
		for i := 0; i < rep; i++ {
			dst = append(dst, seq...)
		}
	}
	return dst
}

// vkSequence maps navigation keys to xterm sequences (non-VT consoles).
func vkSequence(vk coninput.VirtualKeyCode, cks coninput.ControlKeyState) []byte {
	m := 1
	if cks&coninput.SHIFT_PRESSED != 0 {
		m += 1
	}
	if cks&(coninput.LEFT_ALT_PRESSED|coninput.RIGHT_ALT_PRESSED) != 0 {
		m += 2
	}
	if cks&(coninput.LEFT_CTRL_PRESSED|coninput.RIGHT_CTRL_PRESSED) != 0 {
		m += 4
	}
	letter := func(f byte) []byte {
		if m == 1 {
			return []byte{0x1b, '[', f}
		}
		return []byte(fmt.Sprintf("\x1b[1;%d%c", m, f))
	}
	tilde := func(n int) []byte {
		if m == 1 {
			return []byte(fmt.Sprintf("\x1b[%d~", n))
		}
		return []byte(fmt.Sprintf("\x1b[%d;%d~", n, m))
	}
	switch vk {
	case coninput.VK_UP:
		return letter('A')
	case coninput.VK_DOWN:
		return letter('B')
	case coninput.VK_RIGHT:
		return letter('C')
	case coninput.VK_LEFT:
		return letter('D')
	case coninput.VK_HOME:
		return letter('H')
	case coninput.VK_END:
		return letter('F')
	case coninput.VK_INSERT:
		return tilde(2)
	case coninput.VK_DELETE:
		return tilde(3)
	case coninput.VK_PRIOR:
		return tilde(5)
	case coninput.VK_NEXT:
		return tilde(6)
	}
	return nil
}

func (c *winConsole) flushInput() error {
	c.pend = nil
	c.hi = 0
	return coninput.FlushConsoleInputBuffer(c.in)
}

func (c *winConsole) enableOutputVT() (func(), bool) {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return func() {}, false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return func() {}, true
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return func() {}, false // legacy console: no escape sequences
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, true
}

func installSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go handleSignal(ch)
}
