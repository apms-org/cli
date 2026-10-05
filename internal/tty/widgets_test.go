package tty

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConfirm(t *testing.T) {
	tests := []struct {
		name    string
		chunks  []chunk
		def     bool
		want    bool
		wantErr error
		echo    string
	}{
		{"y", script("y"), false, true, nil, "y\r\n"},
		{"Y", script("Y"), false, true, nil, "y\r\n"},
		{"n", script("n"), true, false, nil, "n\r\n"},
		{"N", script("N"), true, false, nil, "n\r\n"},
		{"enter default yes", script("\r"), true, true, nil, "y\r\n"},
		{"enter default no", script("\r"), false, false, nil, "n\r\n"},
		{"esc is no", []chunk{{0, "\x1b"}, {time.Second, "y"}}, true, false, nil, "n\r\n"},
		{"other keys ignored", script("x", "\x1b[A", "1", "y"), false, true, nil, "y\r\n"},
		{"alt y ignored", script("\x1by", "n"), true, false, nil, "n\r\n"},
		{"ctrl c", script("\x03"), true, false, ErrInterrupted, "\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term, f, out := newTestTerminal(t, tt.chunks...)
			got, err := term.Confirm(tt.def)
			if got != tt.want || !errors.Is(err, tt.wantErr) {
				t.Fatalf("Confirm = %v, %v; want %v, %v", got, err, tt.want, tt.wantErr)
			}
			if out.String() != tt.echo {
				t.Errorf("echo = %q, want %q", out.String(), tt.echo)
			}
			if f.restores != 1 || term.IsRaw() {
				t.Error("terminal not restored")
			}
		})
	}
}

func TestPause(t *testing.T) {
	tests := []struct {
		name    string
		chunks  []chunk
		wantErr error
	}{
		{"enter", script("\r"), nil},
		{"space", script(" "), nil},
		{"q", script("q"), nil},
		{"esc", []chunk{{0, "\x1b"}}, nil},
		{"other keys ignored", script("x", "\x1b[B", "\r"), nil},
		{"ctrl c", script("\x03"), ErrInterrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term, f, _ := newTestTerminal(t, tt.chunks...)
			if err := term.Pause(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Pause = %v, want %v", err, tt.wantErr)
			}
			if f.restores != 1 || term.IsRaw() {
				t.Error("terminal not restored")
			}
		})
	}
}

var opts3 = []string{"alpha", "beta", "gamma"}

func TestSelect(t *testing.T) {
	five := []string{"a", "b", "c", "d", "e"}
	tests := []struct {
		name    string
		opts    SelectOptions
		chunks  []chunk
		want    int
		wantErr error
	}{
		{"enter initial", SelectOptions{Options: opts3, Initial: 1}, script("\r"), 1, nil},
		{"down", SelectOptions{Options: opts3}, script("\x1b[B\r"), 1, nil},
		{"app-mode down", SelectOptions{Options: opts3}, script("\x1bOB\r"), 1, nil},
		{"up wraps", SelectOptions{Options: opts3}, script("\x1b[A\r"), 2, nil},
		{"j j k", SelectOptions{Options: opts3}, script("j", "j", "k", "\r"), 1, nil},
		{"tab", SelectOptions{Options: opts3}, script("\t\r"), 1, nil},
		{"end", SelectOptions{Options: opts3}, script("\x1b[F\r"), 2, nil},
		{"home", SelectOptions{Options: opts3, Initial: 2}, script("\x1b[H\r"), 0, nil},
		{"digit", SelectOptions{Options: opts3}, script("3\r"), 2, nil},
		{"digit out of range", SelectOptions{Options: opts3}, script("9\r"), 0, nil},
		{"pgdn", SelectOptions{Options: five, PageSize: 2}, script("\x1b[6~\r"), 2, nil},
		{"pgdn clamps", SelectOptions{Options: five, PageSize: 2}, script("\x1b[6~\x1b[6~\x1b[6~\r"), 4, nil},
		{"pgup", SelectOptions{Options: five, PageSize: 2, Initial: 4}, script("\x1b[5~\r"), 2, nil},
		{"esc", SelectOptions{Options: opts3}, []chunk{{0, "\x1b[B"}, {0, "\x1b"}}, -1, ErrCanceled},
		{"ctrl c", SelectOptions{Options: opts3}, script("\x03"), -1, ErrInterrupted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term, f, _ := newTestTerminal(t, tt.chunks...)
			got, err := term.Select(tt.opts)
			if got != tt.want || !errors.Is(err, tt.wantErr) {
				t.Fatalf("Select = %d, %v; want %d, %v", got, err, tt.want, tt.wantErr)
			}
			if f.restores != 1 || term.IsRaw() {
				t.Error("terminal not restored")
			}
		})
	}
}

func TestSelectDrawing(t *testing.T) {
	term, _, out := newTestTerminal(t, script("\x1b[B", "\r")...)
	if _, err := term.Select(SelectOptions{Title: "Pick:", Options: opts3}); err != nil {
		t.Fatal(err)
	}
	o := out.String()
	for _, want := range []string{
		"\x1b[?25l", "Pick:", "\x1b[36m> alpha\x1b[0m", "  beta",
		"\r\x1b[3A",                // redraw moves back to the title line
		"\x1b[36m> beta\x1b[0m",    // new highlight
		"\x1b[J", "Pick: beta\r\n", // cleared and summarised
		"\x1b[?25h",
	} {
		if !strings.Contains(o, want) {
			t.Errorf("output missing %q:\n%q", want, o)
		}
	}
}

func TestSelectScrollsToTerminalHeight(t *testing.T) {
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, strings.Repeat("x", i%7))
	}
	term, _, out := newTestTerminal(t, script("\x1b[F", "\r")...)
	term.sizeFn = func() (int, int) { return 40, 10 }
	got, err := term.Select(SelectOptions{Options: many})
	if err != nil || got != 49 {
		t.Fatalf("Select = %d, %v", got, err)
	}
	if !strings.Contains(out.String(), "43-50 of 50") {
		t.Errorf("expected scrolled footer: %q", out.String())
	}
}

func TestMultiSelect(t *testing.T) {
	tests := []struct {
		name    string
		opts    SelectOptions
		chunks  []chunk
		want    []int
		wantErr error
	}{
		{"none", SelectOptions{Options: opts3}, script("\r"), []int{}, nil},
		{"toggle two", SelectOptions{Options: opts3}, script(" ", "\x1b[B", " ", "\r"), []int{0, 1}, nil},
		{"toggle off", SelectOptions{Options: opts3, Selected: []bool{true, true}}, script(" \r"), []int{1}, nil},
		{"all", SelectOptions{Options: opts3}, script("a\r"), []int{0, 1, 2}, nil},
		{"all twice clears", SelectOptions{Options: opts3}, script("a", "a", "\r"), []int{}, nil},
		{"initial selected", SelectOptions{Options: opts3, Selected: []bool{false, false, true}}, script("\r"), []int{2}, nil},
		{"esc", SelectOptions{Options: opts3}, []chunk{{0, " "}, {0, "\x1b"}}, nil, ErrCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term, _, _ := newTestTerminal(t, tt.chunks...)
			sel := append([]bool(nil), tt.opts.Selected...)
			got, err := term.MultiSelect(tt.opts)
			if !errors.Is(err, tt.wantErr) || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("MultiSelect = %v, %v; want %v, %v", got, err, tt.want, tt.wantErr)
			}
			if !reflect.DeepEqual(sel, tt.opts.Selected) {
				t.Error("caller's Selected slice was modified")
			}
		})
	}
}

func TestSelectNoANSIFallsBackToNumbers(t *testing.T) {
	term, f, out := newTestTerminal(t, script("2\r")...)
	f.ansi = false
	got, err := term.Select(SelectOptions{Options: opts3})
	if err != nil || got != 1 {
		t.Fatalf("Select = %d, %v", got, err)
	}
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "  2) beta\r\n") {
		t.Errorf("output = %q", out.String())
	}
}

func TestNonTTYWidgets(t *testing.T) {
	nt := func(in string) *terminal { return newTerminal(nil, strings.NewReader(in), io.Discard, false) }

	for _, c := range []struct {
		in   string
		def  bool
		want bool
		err  error
	}{
		{"y\n", false, true, nil},
		{"YES\r\n", false, true, nil},
		{" Yes \n", false, true, nil},
		{"\n", true, true, nil},
		{"\n", false, false, nil},
		{"no\n", true, false, nil},
		{"maybe\n", true, false, nil},
		{"y", false, true, nil},
		{"", true, false, io.EOF},
	} {
		got, err := nt(c.in).Confirm(c.def)
		if got != c.want || err != c.err {
			t.Errorf("Confirm(%q, %v) = %v, %v; want %v, %v", c.in, c.def, got, err, c.want, c.err)
		}
	}

	if err := nt("\n").Pause(); err != nil {
		t.Errorf("Pause: %v", err)
	}
	if err := nt("").Pause(); err != nil {
		t.Errorf("Pause at EOF: %v", err)
	}

	for _, c := range []struct {
		in      string
		initial int
		want    int
		bad     bool
	}{
		{"2\n", 0, 1, false},
		{"\n", 2, 2, false},
		{" 3 \n", 0, 2, false},
		{"9\n", 0, -1, true},
		{"x\n", 0, -1, true},
	} {
		got, err := nt(c.in).Select(SelectOptions{Options: opts3, Initial: c.initial})
		if got != c.want || (err != nil) != c.bad {
			t.Errorf("Select(%q) = %d, %v; want %d (error %v)", c.in, got, err, c.want, c.bad)
		}
	}
	if _, err := nt("").Select(SelectOptions{Options: opts3}); err != io.EOF {
		t.Errorf("Select at EOF: %v", err)
	}
	if _, err := nt("1\n").Select(SelectOptions{}); err == nil {
		t.Error("Select with no options should fail")
	}

	for _, c := range []struct {
		in   string
		sel  []bool
		want []int
		bad  bool
	}{
		{"1,3\n", nil, []int{0, 2}, false},
		{"3 1\n", nil, []int{0, 2}, false},
		{"2-3\n", nil, []int{1, 2}, false},
		{"all\n", nil, []int{0, 1, 2}, false},
		{"none\n", []bool{true}, []int{}, false},
		{"\n", []bool{false, true}, []int{1}, false},
		{"4\n", nil, nil, true},
		{"0\n", nil, nil, true},
	} {
		got, err := nt(c.in).MultiSelect(SelectOptions{Options: opts3, Selected: c.sel})
		if (err != nil) != c.bad || (!c.bad && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("MultiSelect(%q) = %v, %v; want %v (error %v)", c.in, got, err, c.want, c.bad)
		}
	}
}

func TestNonTTYSelectPrintsNumberedList(t *testing.T) {
	out := &syncBuffer{}
	term := newTerminal(nil, strings.NewReader("\n"), out, false)
	if _, err := term.Select(SelectOptions{Title: "Pick", Options: opts3, Initial: 1}); err != nil {
		t.Fatal(err)
	}
	want := "Pick\n  1) alpha\n  2) beta\n  3) gamma\nSelect [1-3] (default 2): "
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}
