package tty

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/mattn/go-runewidth"
)

// LineOptions configures ReadLine.
type LineOptions struct {
	// Prompt is printed by ReadLine and redrawn with the line. Pass it here
	// (instead of printing it yourself) so long lines that wrap are redrawn
	// correctly. It may contain colours and earlier lines ("\n").
	Prompt string
	// Hidden disables echo (passwords). Mask, if non-zero, is echoed once
	// per character instead.
	Hidden bool
	Mask   rune
	// Initial pre-fills the line, with the cursor at its end.
	Initial string
	// MaxLen limits the line to this many characters (0 = no limit).
	MaxLen int
	// KeepSpace returns the line verbatim instead of trimming outer
	// whitespace.
	KeepSpace bool
}

// ReadLine reads one line of input.
//
// On a terminal it runs a raw-mode line editor: typing inserts at the
// cursor; Left/Right, Home/End, Ctrl+A/Ctrl+E move; Backspace/Delete
// delete; Ctrl+U clears the line, Ctrl+W deletes the previous word, Ctrl+K
// deletes to the end; a bracketed paste is inserted literally with CR/LF
// turned into spaces; Enter submits; Esc returns ErrCanceled; Ctrl+C
// returns ErrInterrupted; Ctrl+D on an empty line returns io.EOF.
//
// When stdin is not a terminal it reads a line from the shared reader
// (io.EOF only if nothing was read). Hidden input from a mintty pipe
// returns ErrNoHiddenInput. Outer whitespace is trimmed unless KeepSpace.
func ReadLine(opts LineOptions) (string, error) { return get().ReadLine(opts) }

func (t *terminal) ReadLine(o LineOptions) (string, error) {
	var s string
	var err error
	if t.con == nil {
		if o.Hidden && t.noHidden {
			return "", ErrNoHiddenInput
		}
		t.write(o.Prompt)
		s, err = t.readLineNonTTY()
	} else {
		var restore func()
		restore, err = t.EnterRaw()
		if err != nil {
			return "", err
		}
		s, err = newEditor(t, o).run()
		restore()
	}
	if err != nil {
		return "", err
	}
	if !o.KeepSpace {
		s = strings.TrimSpace(s)
	}
	return s, nil
}

type renderMode int

const (
	renderNone  renderMode = iota // no echo at all
	renderBasic                   // relative redraw with \b and spaces, no escapes
	renderANSI                    // full prompt-relative redraw with escapes
)

type editor struct {
	t    *terminal
	o    LineOptions
	mode renderMode

	buf []rune
	pos int

	promptHead string // prompt up to and including its last "\n"
	promptLine string // last line of the prompt (redrawn)
	promptW    int

	// renderANSI: row of the cursor relative to the prompt's row.
	row int
	// renderBasic: cells shown and cursor cell, relative to the text start.
	shown, cur int
}

func newEditor(t *terminal, o LineOptions) *editor {
	e := &editor{t: t, o: o}
	switch {
	case !t.outTTY, o.Hidden && o.Mask == 0:
		e.mode = renderNone
	case t.isANSI() && o.Prompt != "":
		e.mode = renderANSI
	default:
		e.mode = renderBasic
	}
	if i := strings.LastIndexByte(o.Prompt, '\n'); i >= 0 {
		e.promptHead, e.promptLine = o.Prompt[:i+1], o.Prompt[i+1:]
	} else {
		e.promptLine = o.Prompt
	}
	e.promptW = stringWidth(stripANSI(e.promptLine))
	e.buf = []rune(o.Initial)
	if o.MaxLen > 0 && len(e.buf) > o.MaxLen {
		e.buf = e.buf[:o.MaxLen]
	}
	e.pos = len(e.buf)
	return e
}

func (e *editor) run() (string, error) {
	pasteChanged := e.t.setPaste(true)
	defer func() {
		if pasteChanged {
			e.t.setPaste(false)
		}
	}()
	e.start()
	for {
		k, err := e.t.readKey()
		if err != nil {
			e.finish()
			return "", err
		}
		switch k.Type {
		case KeyEnter:
			e.finish()
			return string(e.buf), nil
		case KeyEsc:
			e.finish()
			return "", ErrCanceled
		case KeyResume:
			e.start()
			continue
		}
		if k.IsCtrl('d') && len(e.buf) == 0 {
			e.finish()
			return "", io.EOF
		}
		if e.handle(k) {
			e.render()
		}
	}
}

// handle applies k to the buffer and reports whether it changed anything.
func (e *editor) handle(k Key) bool {
	alt := k.Mod&(ModAlt|ModMeta) != 0
	switch k.Type {
	case KeyRune:
		if k.Mod&(ModAlt|ModCtrl|ModMeta) == 0 {
			return e.insert([]rune{k.Rune})
		}
		if k.Mod&(ModAlt|ModMeta) != 0 {
			switch k.Rune {
			case 'b':
				return e.moveTo(e.wordLeft())
			case 'f':
				return e.moveTo(e.wordRight())
			case 'd':
				return e.deleteRange(e.pos, e.wordRight())
			}
		}
	case KeyPaste:
		return e.insert(sanitizePaste(k.Paste))
	case KeyBackspace:
		if alt || k.Mod&ModCtrl != 0 {
			return e.deleteRange(e.wordLeft(), e.pos)
		}
		return e.deleteRange(e.pos-1, e.pos)
	case KeyDelete:
		return e.deleteRange(e.pos, e.pos+1)
	case KeyLeft:
		if alt || k.Mod&ModCtrl != 0 {
			return e.moveTo(e.wordLeft())
		}
		return e.moveTo(e.pos - 1)
	case KeyRight:
		if alt || k.Mod&ModCtrl != 0 {
			return e.moveTo(e.wordRight())
		}
		return e.moveTo(e.pos + 1)
	case KeyHome:
		return e.moveTo(0)
	case KeyEnd:
		return e.moveTo(len(e.buf))
	case KeyCtrl:
		switch k.Rune {
		case 'a':
			return e.moveTo(0)
		case 'e':
			return e.moveTo(len(e.buf))
		case 'b':
			return e.moveTo(e.pos - 1)
		case 'f':
			return e.moveTo(e.pos + 1)
		case 'u':
			return e.deleteRange(0, len(e.buf))
		case 'k':
			return e.deleteRange(e.pos, len(e.buf))
		case 'w':
			return e.deleteRange(e.wordLeft(), e.pos)
		case 'd':
			return e.deleteRange(e.pos, e.pos+1)
		case 'l':
			return true
		}
	}
	return false
}

func (e *editor) insert(rs []rune) bool {
	if e.o.MaxLen > 0 {
		room := e.o.MaxLen - len(e.buf)
		if room <= 0 {
			return false
		}
		if len(rs) > room {
			rs = rs[:room]
		}
	}
	if len(rs) == 0 {
		return false
	}
	nb := make([]rune, 0, len(e.buf)+len(rs))
	nb = append(nb, e.buf[:e.pos]...)
	nb = append(nb, rs...)
	nb = append(nb, e.buf[e.pos:]...)
	e.buf = nb
	e.pos += len(rs)
	return true
}

func (e *editor) deleteRange(from, to int) bool {
	if from < 0 {
		from = 0
	}
	if to > len(e.buf) {
		to = len(e.buf)
	}
	if from >= to {
		return false
	}
	e.buf = append(e.buf[:from], e.buf[to:]...)
	if e.pos > to {
		e.pos -= to - from
	} else if e.pos > from {
		e.pos = from
	}
	return true
}

func (e *editor) moveTo(p int) bool {
	if p < 0 {
		p = 0
	}
	if p > len(e.buf) {
		p = len(e.buf)
	}
	if p == e.pos {
		return false
	}
	e.pos = p
	return true
}

func (e *editor) wordLeft() int {
	i := e.pos
	for i > 0 && unicode.IsSpace(e.buf[i-1]) {
		i--
	}
	for i > 0 && !unicode.IsSpace(e.buf[i-1]) {
		i--
	}
	return i
}

func (e *editor) wordRight() int {
	i := e.pos
	for i < len(e.buf) && unicode.IsSpace(e.buf[i]) {
		i++
	}
	for i < len(e.buf) && !unicode.IsSpace(e.buf[i]) {
		i++
	}
	return i
}

// ---- rendering -----------------------------------------------------------

// display returns what is shown for rs, and its width in cells.
func (e *editor) display(rs []rune) (string, int) {
	var sb strings.Builder
	w := 0
	for _, r := range rs {
		if e.o.Hidden {
			r = e.o.Mask
		}
		if r == '\t' || r < 0x20 || r == 0x7f {
			r = ' '
		}
		rw := runewidth.RuneWidth(r)
		if rw == 0 && !unicode.Is(unicode.Mn, r) {
			rw = 1
		}
		sb.WriteRune(r)
		w += rw
	}
	return sb.String(), w
}

// start draws the prompt and the line from scratch.
func (e *editor) start() {
	e.row, e.shown, e.cur = 0, 0, 0
	e.t.write(crlf(e.promptHead))
	switch e.mode {
	case renderANSI:
		e.render()
	case renderBasic, renderNone:
		e.t.write(e.promptLine)
		e.render()
	}
}

func (e *editor) render() {
	switch e.mode {
	case renderANSI:
		e.renderANSI()
	case renderBasic:
		e.renderBasic()
	}
}

func (e *editor) renderANSI() {
	w, _ := e.t.size()
	text, textW := e.display(e.buf)
	_, curW := e.display(e.buf[:e.pos])
	var sb strings.Builder
	if e.row > 0 {
		fmt.Fprintf(&sb, "\x1b[%dA", e.row)
	}
	sb.WriteString("\r\x1b[J")
	sb.WriteString(e.promptLine)
	sb.WriteString(text)
	total := e.promptW + textW
	if total > 0 && total%w == 0 {
		// The cursor sits in the "pending wrap" state on the last column;
		// force it onto the next row so the arithmetic below holds.
		sb.WriteString("\r\n")
	}
	endRow := total / w
	cur := e.promptW + curW
	curRow, curCol := cur/w, cur%w
	if endRow > curRow {
		fmt.Fprintf(&sb, "\x1b[%dA", endRow-curRow)
	}
	sb.WriteString("\r")
	if curCol > 0 {
		fmt.Fprintf(&sb, "\x1b[%dC", curCol)
	}
	e.row = curRow
	e.t.write(sb.String())
}

func (e *editor) renderBasic() {
	text, textW := e.display(e.buf)
	_, curW := e.display(e.buf[:e.pos])
	var sb strings.Builder
	sb.WriteString(strings.Repeat("\b", e.cur))
	sb.WriteString(text)
	if pad := e.shown - textW; pad > 0 {
		sb.WriteString(strings.Repeat(" ", pad))
		sb.WriteString(strings.Repeat("\b", pad))
	}
	sb.WriteString(strings.Repeat("\b", textW-curW))
	e.shown, e.cur = textW, curW
	e.t.write(sb.String())
}

// finish moves past the line and prints a newline.
func (e *editor) finish() {
	if !e.t.outTTY {
		return
	}
	switch e.mode {
	case renderANSI:
		w, _ := e.t.size()
		_, textW := e.display(e.buf)
		total := e.promptW + textW
		if endRow := total / w; endRow > e.row {
			e.t.write(fmt.Sprintf("\x1b[%dB", endRow-e.row))
		}
		if total > 0 && total%w == 0 {
			e.t.write("\r") // render already moved onto a fresh row
			return
		}
	case renderBasic:
		text, _ := e.display(e.buf[e.pos:])
		e.t.write(text)
	}
	e.t.write("\r\n")
}

// sanitizePaste turns pasted text into insertable runes: CR, LF and CRLF
// become a space, other control characters are dropped (tabs are kept).
func sanitizePaste(s string) []rune {
	s = strings.ReplaceAll(s, "\r\n", " ")
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n':
			out = append(out, ' ')
		case r == '\t':
			out = append(out, r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '�':
		default:
			out = append(out, r)
		}
	}
	return out
}

func stringWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runewidth.RuneWidth(r)
	}
	return w
}

// stripANSI removes CSI and OSC escape sequences.
func stripANSI(s string) string {
	if !strings.ContainsRune(s, 0x1b) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != 0x1b || i+1 >= len(s) {
			sb.WriteByte(c)
			continue
		}
		switch s[i+1] {
		case '[':
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j
		case ']':
			j := i + 2
			for j < len(s) && s[j] != 0x07 && !(s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\') {
				j++
			}
			if j < len(s) && s[j] == 0x1b {
				j++
			}
			i = j
		default:
			i++
		}
	}
	return sb.String()
}
