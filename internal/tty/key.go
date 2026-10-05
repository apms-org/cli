// Package tty is the single place the pm CLI reads keyboard input from.
//
// It decodes the byte encodings sent by every common terminal (xterm, VTE,
// konsole, rxvt, kitty, alacritty, Terminal.app, iTerm2, tmux, screen, the
// Linux console, Windows Terminal and the legacy Windows console) into Keys,
// tells a lone Esc apart from the start of an escape sequence with a short
// timeout, and builds a line editor and small widgets (confirm, pause, select)
// on top of that.
//
// When stdin is not an interactive terminal (pipes, CI, tests) every helper
// falls back to reading lines from one shared bufio.Reader on os.Stdin, with
// no raw mode and no escape decoding.
//
// Nothing in this package reads stdin in the background: input is only read
// synchronously, inside a call, so a full-screen program (bubbletea) can take
// over the terminal between calls. Call Discard before handing it over.
//
// All reading functions must be called from one goroutine at a time.
package tty

import (
	"errors"
	"fmt"
)

var (
	// ErrCanceled is returned when the user presses Esc.
	ErrCanceled = errors.New("cancelled")
	// ErrInterrupted is returned when the user presses Ctrl+C while the
	// terminal is in raw mode (where Ctrl+C does not raise SIGINT).
	ErrInterrupted = errors.New("interrupted")
	// ErrNoHiddenInput is returned for hidden prompts when stdin is a mintty
	// pipe (Git Bash / MSYS2 / Cygwin without a pseudo console), where echo
	// cannot be turned off.
	ErrNoHiddenInput = errors.New("this terminal cannot hide what you type (mintty without a pseudo console). " +
		"Run `winpty pm ...`, use Windows Terminal, or reinstall Git for Windows with " +
		"\"Enable experimental support for pseudo consoles\" checked")
	// ErrNotTerminal is returned by key-level functions (ReadKey,
	// ReadKeyTimeout, EnterRaw) when stdin is not an interactive terminal.
	ErrNotTerminal = errors.New("stdin is not an interactive terminal")
)

// KeyType identifies a decoded key.
type KeyType int

const (
	// KeyIgnore is a sequence that was recognised and deliberately dropped
	// (focus reports, mouse reports, F-keys, ...). ReadKey never returns it.
	KeyIgnore KeyType = iota
	KeyRune           // printable character in Key.Rune
	KeyEnter
	KeyEsc
	KeyBackspace
	KeyDelete
	KeyTab
	KeyShiftTab
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyPgUp
	KeyPgDn
	KeyCtrl   // Ctrl+letter (or Ctrl+\ ] ^ _); lower-case letter in Key.Rune
	KeyPaste  // bracketed paste; payload in Key.Paste
	KeyResume // the process was suspended (Ctrl+Z) and resumed; redraw
)

var keyNames = [...]string{
	KeyIgnore: "Ignore", KeyRune: "Rune", KeyEnter: "Enter", KeyEsc: "Esc",
	KeyBackspace: "Backspace", KeyDelete: "Delete", KeyTab: "Tab",
	KeyShiftTab: "ShiftTab", KeyUp: "Up", KeyDown: "Down", KeyLeft: "Left",
	KeyRight: "Right", KeyHome: "Home", KeyEnd: "End", KeyPgUp: "PgUp",
	KeyPgDn: "PgDn", KeyCtrl: "Ctrl", KeyPaste: "Paste", KeyResume: "Resume",
}

func (t KeyType) String() string {
	if t >= 0 && int(t) < len(keyNames) {
		return keyNames[t]
	}
	return fmt.Sprintf("KeyType(%d)", int(t))
}

// Mod is a set of modifier keys.
type Mod uint8

const (
	ModShift Mod = 1 << iota
	ModAlt
	ModCtrl
	ModMeta
)

func (m Mod) String() string {
	s := ""
	if m&ModCtrl != 0 {
		s += "Ctrl+"
	}
	if m&ModAlt != 0 {
		s += "Alt+"
	}
	if m&ModShift != 0 {
		s += "Shift+"
	}
	if m&ModMeta != 0 {
		s += "Meta+"
	}
	return s
}

// Key is one decoded key press.
type Key struct {
	Type  KeyType
	Rune  rune   // KeyRune: the character; KeyCtrl: the lower-case letter
	Mod   Mod    // modifiers, when the terminal reported them
	Paste string // KeyPaste: the pasted text, verbatim
}

func (k Key) String() string {
	switch k.Type {
	case KeyRune:
		return fmt.Sprintf("%s%q", k.Mod, k.Rune)
	case KeyCtrl:
		return fmt.Sprintf("%sCtrl(%c)", k.Mod&^ModCtrl, k.Rune)
	case KeyPaste:
		return fmt.Sprintf("Paste(%q)", k.Paste)
	}
	return k.Mod.String() + k.Type.String()
}

// IsCtrl reports whether k is Ctrl+c (c is a lower-case letter).
func (k Key) IsCtrl(c rune) bool { return k.Type == KeyCtrl && k.Rune == c }

// IsRune reports whether k is the plain (no Alt/Ctrl/Meta) character r.
func (k Key) IsRune(r rune) bool {
	return k.Type == KeyRune && k.Rune == r && k.Mod&(ModAlt|ModCtrl|ModMeta) == 0
}
