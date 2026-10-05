package tty

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// console is an interactive terminal on stdin.
type console interface {
	source
	// makeRaw puts the terminal in raw mode and returns a function that
	// restores the previous mode.
	makeRaw() (restore func() error, err error)
	// flushInput discards input queued in the OS and in the console.
	flushInput() error
	// enableOutputVT prepares stdout for escape sequences (Windows:
	// ENABLE_VIRTUAL_TERMINAL_PROCESSING) and reports whether they work.
	enableOutputVT() (restore func(), ok bool)
}

// terminal holds all state. The package-level functions use one instance
// bound to os.Stdin/os.Stdout; tests build their own.
type terminal struct {
	con      console       // nil when stdin is not interactive
	out      io.Writer     // where prompts and echo go
	outTTY   bool          // out is a terminal (echo is visible)
	noHidden bool          // stdin is a mintty pipe: echo cannot be disabled
	lines    *bufio.Reader // non-interactive line source
	keys     *keyReader
	sizeFn   func() (w, h int)
	// canSuspend reports whether Ctrl+Z may stop the process now; suspend
	// stops it and returns after SIGCONT. Both nil where unsupported.
	canSuspend func() bool
	suspend    func()

	mu           sync.Mutex // guards the fields below
	raw          bool
	rawRestore   func() error
	vtRestore    func()
	ansi         bool // escape sequences may be written (valid while raw)
	pasteOn      bool
	cursorHidden bool
}

var (
	stdOnce sync.Once
	std     *terminal
	osExit  = os.Exit
)

func get() *terminal {
	stdOnce.Do(func() {
		con, noHidden := openConsole()
		std = &terminal{
			out:      os.Stdout,
			outTTY:   term.IsTerminal(int(os.Stdout.Fd())),
			noHidden: noHidden,
			lines:    bufio.NewReader(os.Stdin),
			sizeFn:   osSize,
		}
		if con != nil {
			std.con = con
			std.keys = newKeyReader(con, escTimeoutFromEnv())
			std.canSuspend, std.suspend = suspendFuncs(con)
		}
	})
	return std
}

// newTerminal builds a terminal for tests: con may be nil for line mode.
func newTerminal(con console, in io.Reader, out io.Writer, outTTY bool) *terminal {
	t := &terminal{
		con:    con,
		out:    out,
		outTTY: outTTY,
		lines:  bufio.NewReader(in),
		sizeFn: func() (int, int) { return 80, 24 },
	}
	if con != nil {
		t.keys = newKeyReader(con, defaultEscTimeout)
	}
	return t
}

func osSize() (int, int) {
	for _, f := range []*os.File{os.Stdout, os.Stderr, os.Stdin} {
		if w, h, err := term.GetSize(int(f.Fd())); err == nil && w > 0 && h > 0 {
			return w, h
		}
	}
	w, _ := strconv.Atoi(os.Getenv("COLUMNS"))
	h, _ := strconv.Atoi(os.Getenv("LINES"))
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	return w, h
}

func (t *terminal) size() (int, int) {
	w, h := t.sizeFn()
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	return w, h
}

// ---- raw mode ----------------------------------------------------------

func (t *terminal) IsRaw() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.raw
}

func (t *terminal) isANSI() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ansi
}

func (t *terminal) EnterRaw() (func(), error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.con == nil {
		return func() {}, ErrNotTerminal
	}
	if t.raw {
		return func() {}, nil
	}
	if err := t.enterRawLocked(); err != nil {
		return func() {}, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			t.restoreLocked()
			t.mu.Unlock()
		})
	}, nil
}

func (t *terminal) enterRawLocked() error {
	restore, err := t.con.makeRaw()
	if err != nil {
		return fmt.Errorf("tty: raw mode: %w", err)
	}
	t.rawRestore = restore
	t.raw = true
	vt, ok := t.con.enableOutputVT()
	t.vtRestore = vt
	t.ansi = ok && t.outTTY
	return nil
}

// restoreLocked undoes everything we changed. Idempotent.
func (t *terminal) restoreLocked() {
	if t.pasteOn {
		io.WriteString(t.out, "\x1b[?2004l")
		t.pasteOn = false
	}
	if t.cursorHidden {
		io.WriteString(t.out, "\x1b[?25h")
		t.cursorHidden = false
	}
	if t.vtRestore != nil {
		t.vtRestore()
		t.vtRestore = nil
	}
	if t.raw {
		if t.rawRestore != nil {
			_ = t.rawRestore()
		}
		t.rawRestore = nil
		t.raw = false
	}
	t.ansi = false
}

func (t *terminal) Restore() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.restoreLocked()
}

// setPaste turns bracketed paste on or off (only while raw with ANSI
// output). It returns whether the state changed.
func (t *terminal) setPaste(on bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.raw || !t.ansi || t.pasteOn == on {
		return false
	}
	if on {
		io.WriteString(t.out, "\x1b[?2004h")
	} else {
		io.WriteString(t.out, "\x1b[?2004l")
	}
	t.pasteOn = on
	return true
}

func (t *terminal) setCursorHidden(hidden bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.raw || !t.ansi || t.cursorHidden == hidden {
		return false
	}
	if hidden {
		io.WriteString(t.out, "\x1b[?25l")
	} else {
		io.WriteString(t.out, "\x1b[?25h")
	}
	t.cursorHidden = hidden
	return true
}

// doSuspend stops the process (Ctrl+Z) with the terminal restored and
// re-applies raw mode (and paste / cursor state) after SIGCONT.
func (t *terminal) doSuspend() bool {
	if t.suspend == nil || t.canSuspend == nil || !t.canSuspend() {
		return false
	}
	t.mu.Lock()
	if !t.raw {
		t.mu.Unlock()
		return false
	}
	paste, hidden := t.pasteOn, t.cursorHidden
	t.restoreLocked()
	t.mu.Unlock()

	t.suspend()

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.enterRawLocked(); err != nil {
		return true
	}
	if paste && t.ansi {
		io.WriteString(t.out, "\x1b[?2004h")
		t.pasteOn = true
	}
	if hidden && t.ansi {
		io.WriteString(t.out, "\x1b[?25l")
		t.cursorHidden = true
	}
	return true
}

// ---- keys --------------------------------------------------------------

// nextKey reads one key; the terminal must already be raw. Ctrl+C returns
// ErrInterrupted (with the key); Ctrl+Z suspends where supported.
func (t *terminal) nextKey(deadline time.Time) (Key, bool, error) {
	k, ok, err := t.keys.next(deadline)
	if err != nil || !ok {
		return k, ok, err
	}
	if k.IsCtrl('c') {
		return k, true, ErrInterrupted
	}
	if k.IsCtrl('z') && t.doSuspend() {
		return Key{Type: KeyResume}, true, nil
	}
	return k, true, nil
}

func (t *terminal) readKey() (Key, error) {
	k, _, err := t.nextKey(time.Time{})
	return k, err
}

func (t *terminal) ReadKey() (Key, error) {
	if t.con == nil {
		return Key{}, ErrNotTerminal
	}
	restore, err := t.EnterRaw()
	if err != nil {
		return Key{}, err
	}
	defer restore()
	return t.readKey()
}

func (t *terminal) ReadKeyTimeout(d time.Duration) (Key, bool, error) {
	if t.con == nil {
		return Key{}, false, ErrNotTerminal
	}
	restore, err := t.EnterRaw()
	if err != nil {
		return Key{}, false, err
	}
	defer restore()
	if d < 0 {
		d = 0
	}
	return t.nextKey(time.Now().Add(d))
}

func (t *terminal) Discard() {
	if t.con == nil {
		return
	}
	t.keys.reset()
	_ = t.con.flushInput()
}

// ---- output ------------------------------------------------------------

func (t *terminal) write(s string) {
	if s != "" {
		io.WriteString(t.out, s)
	}
}

// crlf converts bare \n to \r\n.
func crlf(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func (t *terminal) Printf(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	if t.IsRaw() {
		s = crlf(s)
	}
	t.write(s)
}

// ---- line input (non-interactive) ---------------------------------------

// readLineNonTTY reads one line from the shared reader, without the
// trailing \r\n. io.EOF is returned only when nothing was read.
func (t *terminal) readLineNonTTY() (string, error) {
	s, err := t.lines.ReadString('\n')
	if err != nil {
		if err != io.EOF || s == "" {
			return "", err
		}
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// ---- package API ---------------------------------------------------------

// Interactive reports whether stdin is a real terminal/console that can be
// put in raw mode. It is false for pipes, files and mintty pipes.
func Interactive() bool { return get().con != nil }

// EnterRaw puts the terminal in raw mode. It nests: if the terminal is
// already raw it returns a no-op restore. The restore function returned by
// the outermost call returns the terminal to its state before that call
// (and is safe to call more than once). Returns ErrNotTerminal when stdin
// is not interactive.
func EnterRaw() (restore func(), err error) { return get().EnterRaw() }

// IsRaw reports whether this package currently has the terminal in raw mode.
func IsRaw() bool { return get().IsRaw() }

// ReadKey waits for one key, entering raw mode for the call if needed. It
// never returns KeyIgnore. Ctrl+C returns ErrInterrupted.
func ReadKey() (Key, error) { return get().ReadKey() }

// ReadKeyTimeout is ReadKey with a timeout: ok=false (and a nil error) when
// d passes without a key. d <= 0 polls.
func ReadKeyTimeout(d time.Duration) (key Key, ok bool, err error) { return get().ReadKeyTimeout(d) }

// Discard drops pending input, both ours and the OS queue. Call it before
// handing the terminal to another reader such as bubbletea.
func Discard() { get().Discard() }

// Restore returns the terminal to the state it had before raw mode (and
// shows the cursor, disables bracketed paste). Safe to call any time, any
// number of times, from any goroutine.
func Restore() { get().Restore() }

// Exit restores the terminal and exits the process with code.
func Exit(code int) {
	Restore()
	osExit(code)
}

// Printf writes to stdout, converting \n to \r\n while the terminal is raw.
func Printf(format string, a ...any) { get().Printf(format, a...) }

// Width returns the terminal width in columns (80 if unknown).
func Width() int { w, _ := get().size(); return w }

// Height returns the terminal height in rows (24 if unknown).
func Height() int { _, h := get().size(); return h }

// LineReader returns the shared reader used for non-interactive line input.
// Code that still reads stdin line by line itself must use this reader so
// that buffered input is not split between two readers.
func LineReader() *bufio.Reader { return get().lines }

var sigOnce sync.Once

// InstallSignalHandler (once) arranges for SIGINT, SIGTERM (and SIGHUP on
// Unix) to restore the terminal and exit with 128+signal.
func InstallSignalHandler() {
	sigOnce.Do(installSignalHandler)
}
