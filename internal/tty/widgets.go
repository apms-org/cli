package tty

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/mattn/go-runewidth"
)

// Pause waits for the user to continue. On a terminal Enter, Esc, Space
// and q all continue (Ctrl+C returns ErrInterrupted); otherwise it reads a
// line (EOF also continues).
func Pause() error { return get().Pause() }

func (t *terminal) Pause() error {
	if t.con == nil {
		_, err := t.readLineNonTTY()
		if err == io.EOF {
			return nil
		}
		return err
	}
	restore, err := t.EnterRaw()
	if err != nil {
		return err
	}
	defer restore()
	for {
		k, err := t.readKey()
		if err != nil {
			t.newline()
			return err
		}
		switch {
		case k.Type == KeyEnter, k.Type == KeyEsc, k.IsRune(' '), k.IsRune('q'), k.IsRune('Q'):
			t.newline()
			return nil
		}
	}
}

func (t *terminal) newline() {
	if t.outTTY {
		t.write("\r\n")
	}
}

// Confirm asks a yes/no question; the caller prints the question. On a
// terminal it reads one key: y/Y yes, n/N no, Enter the default, Esc no
// (without an error), Ctrl+C ErrInterrupted; the answer is echoed.
// Otherwise it reads a line: "y"/"yes" (any case) is yes, a blank line is
// the default, anything else is no; EOF returns (false, io.EOF).
func Confirm(defaultYes bool) (bool, error) { return get().Confirm(defaultYes) }

func (t *terminal) Confirm(defaultYes bool) (bool, error) {
	if t.con == nil {
		s, err := t.readLineNonTTY()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		}
		return false, nil
	}
	restore, err := t.EnterRaw()
	if err != nil {
		return false, err
	}
	defer restore()
	for {
		k, err := t.readKey()
		if err != nil {
			t.newline()
			return false, err
		}
		var yes bool
		switch {
		case k.IsRune('y'), k.IsRune('Y'):
			yes = true
		case k.IsRune('n'), k.IsRune('N'), k.Type == KeyEsc:
			yes = false
		case k.Type == KeyEnter:
			yes = defaultYes
		default:
			continue
		}
		if t.outTTY {
			if yes {
				t.write("y\r\n")
			} else {
				t.write("n\r\n")
			}
		}
		return yes, nil
	}
}

// SelectOptions configures Select and MultiSelect.
type SelectOptions struct {
	Title    string   // printed above the list (optional)
	Options  []string // the choices
	Initial  int      // initially highlighted (Select: default choice)
	Multi    bool     // set by MultiSelect
	Selected []bool   // MultiSelect: initially checked options
	PageSize int      // rows shown at once (0 = all that fit)
}

var errNoOptions = errors.New("tty: no options to select from")

// Select shows a list and returns the chosen index. On a terminal: Up/Down
// (or k/j), Home/End, PgUp/PgDn, digits 1-9 jump, Enter chooses, Esc
// returns ErrCanceled. The list is drawn in place starting at the current
// line and scrolls when it is taller than PageSize or the terminal.
// Otherwise it prints numbered options and reads a number (blank = Initial).
func Select(opts SelectOptions) (int, error) { return get().Select(opts) }

// MultiSelect is Select with check boxes: Space toggles, a toggles all,
// Enter confirms. It returns the checked indices in order. Without a
// terminal it reads a list like "1,3 5-7", "all" or "none" (blank keeps
// Selected).
func MultiSelect(opts SelectOptions) ([]int, error) { return get().MultiSelect(opts) }

func (t *terminal) Select(o SelectOptions) (int, error) {
	o.Multi = false
	idx, err := t.runSelect(o)
	if err != nil {
		return -1, err
	}
	return idx[0], nil
}

func (t *terminal) MultiSelect(o SelectOptions) ([]int, error) {
	o.Multi = true
	return t.runSelect(o)
}

func (t *terminal) runSelect(o SelectOptions) ([]int, error) {
	n := len(o.Options)
	if n == 0 {
		return nil, errNoOptions
	}
	if o.Initial < 0 || o.Initial >= n {
		o.Initial = 0
	}
	sel := make([]bool, n)
	copy(sel, o.Selected)
	o.Selected = sel
	if t.con == nil || !t.outTTY {
		return t.selectNumbered(o)
	}
	restore, err := t.EnterRaw()
	if err != nil {
		return nil, err
	}
	defer restore()
	if !t.isANSI() {
		return t.selectNumbered(o)
	}
	l := &list{t: t, o: o, cur: o.Initial}
	return l.run()
}

// ---- numbered fallback -----------------------------------------------------

func (t *terminal) selectNumbered(o SelectOptions) ([]int, error) {
	var sb strings.Builder
	if o.Title != "" {
		sb.WriteString(o.Title + "\n")
	}
	for i, opt := range o.Options {
		mark := ""
		if o.Multi {
			mark = "[ ] "
			if o.Selected[i] {
				mark = "[x] "
			}
		}
		fmt.Fprintf(&sb, "  %d) %s%s\n", i+1, mark, opt)
	}
	t.Printf("%s", sb.String())
	n := len(o.Options)
	if !o.Multi {
		s, err := t.ReadLine(LineOptions{Prompt: fmt.Sprintf("Select [1-%d] (default %d): ", n, o.Initial+1)})
		if err != nil {
			return nil, err
		}
		if s == "" {
			return []int{o.Initial}, nil
		}
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 || v > n {
			return nil, fmt.Errorf("invalid selection %q: enter a number from 1 to %d", s, n)
		}
		return []int{v - 1}, nil
	}
	s, err := t.ReadLine(LineOptions{Prompt: "Select numbers (e.g. 1,3 5-7, all, none; blank keeps current): "})
	if err != nil {
		return nil, err
	}
	if s == "" {
		return checked(o.Selected), nil
	}
	return parseNumberList(s, n)
}

func checked(sel []bool) []int {
	out := []int{}
	for i, s := range sel {
		if s {
			out = append(out, i)
		}
	}
	return out
}

func parseNumberList(s string, n int) ([]int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "all", "a", "*":
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out, nil
	case "none", "-":
		return []int{}, nil
	}
	seen := map[int]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		lo, hi := f, f
		if i := strings.IndexByte(f, '-'); i > 0 {
			lo, hi = f[:i], f[i+1:]
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > n || a > b {
			return nil, fmt.Errorf("invalid selection %q: use numbers from 1 to %d", f, n)
		}
		for v := a; v <= b; v++ {
			seen[v-1] = true
		}
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}

// ---- interactive list --------------------------------------------------------

type list struct {
	t     *terminal
	o     SelectOptions
	cur   int
	top   int
	drawn int // lines drawn last time
}

func (l *list) pageSize() int {
	n := len(l.o.Options)
	page := l.o.PageSize
	if page <= 0 || page > n {
		page = n
	}
	_, h := l.t.size()
	avail := h - 2 // footer + one spare row
	if l.o.Title != "" {
		avail--
	}
	if avail < 1 {
		avail = 1
	}
	if page > avail {
		page = avail
	}
	return page
}

func (l *list) lines() []string {
	w, _ := l.t.size()
	maxW := w - 1
	if maxW < 10 {
		maxW = 10
	}
	n := len(l.o.Options)
	page := l.pageSize()
	if l.cur < l.top {
		l.top = l.cur
	}
	if l.cur >= l.top+page {
		l.top = l.cur - page + 1
	}
	var out []string
	if l.o.Title != "" {
		out = append(out, fit(l.o.Title, maxW))
	}
	for i := l.top; i < l.top+page && i < n; i++ {
		prefix := "  "
		if i == l.cur {
			prefix = "> "
		}
		if l.o.Multi {
			if l.o.Selected[i] {
				prefix += "[x] "
			} else {
				prefix += "[ ] "
			}
		}
		line := fit(prefix+l.o.Options[i], maxW)
		if i == l.cur {
			line = "\x1b[36m" + line + "\x1b[0m"
		}
		out = append(out, line)
	}
	var footer []string
	if page < n {
		footer = append(footer, fmt.Sprintf("%d-%d of %d", l.top+1, l.top+page, n))
	}
	if l.o.Multi {
		footer = append(footer, "space: toggle, a: all, enter: confirm, esc: cancel")
	}
	if len(footer) > 0 {
		out = append(out, fit("\x1b[2m  "+strings.Join(footer, " | ")+"\x1b[0m", maxW))
	}
	return out
}

// fit truncates s (which may contain escapes) to maxW cells. Escapes are
// dropped when truncation is needed.
func fit(s string, maxW int) string {
	plain := stripANSI(s)
	if stringWidth(plain) <= maxW {
		return s
	}
	return runewidth.Truncate(plain, maxW, "...")
}

func (l *list) draw() {
	var sb strings.Builder
	if l.drawn > 0 {
		sb.WriteString("\r")
		if l.drawn > 1 {
			fmt.Fprintf(&sb, "\x1b[%dA", l.drawn-1)
		}
	}
	lines := l.lines()
	for i, ln := range lines {
		sb.WriteString("\r\x1b[2K")
		sb.WriteString(ln)
		if i < len(lines)-1 {
			sb.WriteString("\r\n")
		}
	}
	l.drawn = len(lines)
	l.t.write(sb.String())
}

func (l *list) clear() {
	if l.drawn == 0 {
		return
	}
	s := "\r"
	if l.drawn > 1 {
		s += fmt.Sprintf("\x1b[%dA", l.drawn-1)
	}
	l.t.write(s + "\x1b[J")
	l.drawn = 0
}

func (l *list) run() ([]int, error) {
	n := len(l.o.Options)
	if l.t.setCursorHidden(true) {
		defer l.t.setCursorHidden(false)
	}
	l.draw()
	for {
		k, err := l.t.readKey()
		if err != nil {
			l.clear()
			return nil, err
		}
		page := l.pageSize()
		switch {
		case k.Type == KeyUp, k.IsRune('k'), k.IsCtrl('p'), k.Type == KeyShiftTab:
			l.cur = (l.cur - 1 + n) % n
		case k.Type == KeyDown, k.IsRune('j'), k.IsCtrl('n'), k.Type == KeyTab:
			l.cur = (l.cur + 1) % n
		case k.Type == KeyHome, k.IsRune('g'):
			l.cur = 0
		case k.Type == KeyEnd, k.IsRune('G'):
			l.cur = n - 1
		case k.Type == KeyPgUp:
			l.cur = max(l.cur-page, 0)
		case k.Type == KeyPgDn:
			l.cur = min(l.cur+page, n-1)
		case k.Type == KeyRune && k.Mod == 0 && k.Rune >= '1' && k.Rune <= '9':
			if d := int(k.Rune - '1'); d < n {
				l.cur = d
			}
		case l.o.Multi && k.IsRune(' '):
			l.o.Selected[l.cur] = !l.o.Selected[l.cur]
		case l.o.Multi && (k.IsRune('a') || k.IsCtrl('a')):
			all := true
			for _, s := range l.o.Selected {
				all = all && s
			}
			for i := range l.o.Selected {
				l.o.Selected[i] = !all
			}
		case k.Type == KeyEnter:
			l.clear()
			if l.o.Multi {
				res := checked(l.o.Selected)
				names := make([]string, len(res))
				for i, v := range res {
					names[i] = l.o.Options[v]
				}
				l.summary(strings.Join(names, ", "))
				return res, nil
			}
			l.summary(l.o.Options[l.cur])
			return []int{l.cur}, nil
		case k.Type == KeyEsc:
			l.clear()
			return nil, ErrCanceled
		case k.Type == KeyResume:
			l.drawn = 0
		default:
			continue
		}
		l.draw()
	}
}

func (l *list) summary(choice string) {
	w, _ := l.t.size()
	s := choice
	if l.o.Title != "" {
		s = l.o.Title + " " + choice
	}
	l.t.write(fit(s, w-1) + "\r\n")
}
