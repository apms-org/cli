package tty

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadLineEditing(t *testing.T) {
	tests := []struct {
		name  string
		opts  LineOptions
		input []string
		want  string
	}{
		{"typing", LineOptions{}, []string{"hello\r"}, "hello"},
		{"typing key by key", LineOptions{}, []string{"h", "i", "\r"}, "hi"},
		{"backspace", LineOptions{}, []string{"abcd\x7f\x7f\r"}, "ab"},
		{"backspace ctrl-h", LineOptions{}, []string{"abc\x08\r"}, "ab"},
		{"backspace over multibyte", LineOptions{}, []string{"日本語\x7f\r"}, "日本"},
		{"backspace over emoji", LineOptions{}, []string{"a😀\x7fb\r"}, "ab"},
		{"backspace at start", LineOptions{}, []string{"\x7f\x7fa\r"}, "a"},
		{"left insert", LineOptions{}, []string{"ac\x1b[Db\r"}, "abc"},
		{"app-mode left insert", LineOptions{}, []string{"ac\x1bODb\r"}, "abc"},
		{"left right", LineOptions{}, []string{"ab\x1b[D\x1b[D\x1b[CX\r"}, "aXb"},
		{"home insert", LineOptions{}, []string{"bc\x1b[Ha\r"}, "abc"},
		{"end append", LineOptions{}, []string{"ab\x1b[H\x1b[Fc\r"}, "abc"},
		{"ctrl a / ctrl e", LineOptions{}, []string{"bc\x01a\x05d\r"}, "abcd"},
		{"ctrl b / ctrl f", LineOptions{}, []string{"ac\x02b\x06d\r"}, "abcd"},
		{"delete", LineOptions{}, []string{"abc\x1b[D\x1b[D\x1b[3~\r"}, "ac"},
		{"delete at end is no-op", LineOptions{}, []string{"abc\x1b[3~\r"}, "abc"},
		{"ctrl u clears", LineOptions{}, []string{"abc\x15xy\r"}, "xy"},
		{"ctrl u mid-line clears", LineOptions{}, []string{"abc\x1b[D\x15xy\r"}, "xy"},
		{"ctrl w", LineOptions{}, []string{"foo bar\x17baz\r"}, "foo baz"},
		{"ctrl w trailing space", LineOptions{}, []string{"foo bar  \x17\r"}, "foo"},
		{"alt backspace", LineOptions{}, []string{"foo bar\x1b\x7f\r"}, "foo"},
		{"ctrl k", LineOptions{}, []string{"abcdef\x1b[D\x1b[D\x1b[D\x0b\r"}, "abc"},
		{"ctrl left word", LineOptions{}, []string{"foo bar\x1b[1;5DX\r"}, "foo Xbar"},
		{"ctrl d deletes when not empty", LineOptions{}, []string{"ab\x1b[D\x04\r"}, "a"},
		{"paste", LineOptions{}, []string{"\x1b[200~line1\r\nline2\nline3\x1b[201~\r"}, "line1 line2 line3"},
		{"paste mid-line", LineOptions{}, []string{"ad\x1b[D\x1b[200~bc\x1b[201~\r"}, "abcd"},
		{"paste drops control chars", LineOptions{}, []string{"\x1b[200~a\x1bb\x03c\x1b[201~\r"}, "abc"},
		{"ignored keys", LineOptions{}, []string{"a\x1b[I\x1b[11~\x1bOP\tb\r"}, "ab"},
		{"alt rune not inserted", LineOptions{}, []string{"a\x1bxb\r"}, "ab"},
		{"crlf enter", LineOptions{}, []string{"ab\r\n"}, "ab"},
		{"lf enter", LineOptions{}, []string{"ab\n"}, "ab"},
		{"keypad enter", LineOptions{}, []string{"ab\x1bOM"}, "ab"},
		{"kitty enter", LineOptions{}, []string{"ab\x1b[13u"}, "ab"},
		{"trims", LineOptions{}, []string{"  a b  \r"}, "a b"},
		{"keep space", LineOptions{KeepSpace: true}, []string{"  a b  \r"}, "  a b  "},
		{"max len", LineOptions{MaxLen: 3}, []string{"abcdef\r"}, "abc"},
		{"max len paste", LineOptions{MaxLen: 4}, []string{"a\x1b[200~bcdef\x1b[201~\r"}, "abcd"},
		{"initial", LineOptions{Initial: "foo"}, []string{"\x7fx\r"}, "fox"},
		{"initial home", LineOptions{Initial: "oo"}, []string{"\x1b[Hf\r"}, "foo"},
		{"hidden", LineOptions{Hidden: true}, []string{"s3cret\r"}, "s3cret"},
		{"hidden editing", LineOptions{Hidden: true}, []string{"pass\x7fs\x1b[Dx\r"}, "pasxs"},
		{"masked", LineOptions{Hidden: true, Mask: '*'}, []string{"abc\r"}, "abc"},
		{"prompt", LineOptions{Prompt: "Name: "}, []string{"bob\r"}, "bob"},
	}
	for _, ansi := range []bool{true, false} {
		for _, tt := range tests {
			name := tt.name
			if !ansi {
				name += " (no ansi)"
			}
			t.Run(name, func(t *testing.T) {
				term, f, _ := newTestTerminal(t, script(tt.input...)...)
				f.ansi = ansi
				got, err := term.ReadLine(tt.opts)
				if err != nil {
					t.Fatalf("ReadLine: %v", err)
				}
				if got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
				if f.rawCalls != 1 || f.restores != 1 || term.IsRaw() {
					t.Errorf("raw calls %d, restores %d, raw now %v", f.rawCalls, f.restores, term.IsRaw())
				}
			})
		}
	}
}

func TestReadLineErrors(t *testing.T) {
	tests := []struct {
		name   string
		chunks []chunk
		want   error
	}{
		{"esc cancels", []chunk{{0, "abc"}, {0, "\x1b"}}, ErrCanceled},
		{"esc after a pause cancels", []chunk{{0, "abc"}, {time.Second, "\x1b"}, {time.Second, "more\r"}}, ErrCanceled},
		{"ctrl c interrupts", script("abc\x03"), ErrInterrupted},
		{"kitty ctrl c interrupts", script("abc\x1b[99;5u"), ErrInterrupted},
		{"ctrl d on empty is EOF", script("\x04"), io.EOF},
		{"ctrl d after clearing is EOF", script("ab\x15\x04"), io.EOF},
		{"source EOF", script("abc"), io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term, f, out := newTestTerminal(t, tt.chunks...)
			got, err := term.ReadLine(LineOptions{Prompt: "> "})
			if !errors.Is(err, tt.want) || got != "" {
				t.Fatalf("ReadLine = %q, %v; want %v", got, err, tt.want)
			}
			if f.restores != f.rawCalls || term.IsRaw() {
				t.Errorf("terminal left raw")
			}
			if o := strings.TrimSuffix(out.String(), "\x1b[?2004l"); !strings.HasSuffix(o, "\r\n") {
				t.Errorf("output does not end with a newline: %q", out.String())
			}
		})
	}
}

func TestReadLineHiddenNeverEchoes(t *testing.T) {
	for _, ansi := range []bool{true, false} {
		term, f, out := newTestTerminal(t, script("hunter2", "\x1b[D\x7fX", "\x1b[200~pasted\x1b[201~", "\r")...)
		f.ansi = ansi
		got, err := term.ReadLine(LineOptions{Prompt: "PW> ", Hidden: true})
		if err != nil || got != "hunteXpasted2" {
			t.Fatalf("ReadLine = %q, %v", got, err)
		}
		o := strings.NewReplacer("\x1b[?2004h", "", "\x1b[?2004l", "").Replace(out.String())
		if o != "PW> \r\n" {
			t.Errorf("ansi=%v: hidden output = %q, want only the prompt and a newline", ansi, o)
		}
	}
}

func TestReadLineMaskOutput(t *testing.T) {
	term, _, out := newTestTerminal(t, script("abc\r")...)
	if _, err := term.ReadLine(LineOptions{Prompt: "> ", Hidden: true, Mask: '*'}); err != nil {
		t.Fatal(err)
	}
	if o := out.String(); strings.ContainsAny(o, "abc") || !strings.Contains(o, "***") {
		t.Errorf("masked output = %q", o)
	}
}

func TestReadLineANSIOutput(t *testing.T) {
	term, _, out := newTestTerminal(t, script("abc\r")...)
	if _, err := term.ReadLine(LineOptions{Prompt: "Name: "}); err != nil {
		t.Fatal(err)
	}
	o := out.String()
	for _, want := range []string{"\x1b[?2004h", "\r\x1b[JName: abc", "\x1b[?2004l"} {
		if !strings.Contains(o, want) {
			t.Errorf("output %q does not contain %q", o, want)
		}
	}
	if !strings.HasSuffix(o, "\r\n\x1b[?2004l") {
		t.Errorf("output should end with newline then paste off: %q", o)
	}
}

func TestReadLineWrapping(t *testing.T) {
	// 10 columns: prompt (2) + 12 chars wraps onto a second row. Home must
	// move the cursor up one row and to column 2.
	term, _, out := newTestTerminal(t, script("abcdefghijkl", "\x1b[H", "\r")...)
	term.sizeFn = func() (int, int) { return 10, 24 }
	got, err := term.ReadLine(LineOptions{Prompt: "> "})
	if err != nil || got != "abcdefghijkl" {
		t.Fatalf("ReadLine = %q, %v", got, err)
	}
	o := out.String()
	if !strings.Contains(o, "\x1b[1A\r\x1b[2C") {
		t.Errorf("expected cursor up + column 2 after Home: %q", o)
	}
	// Exactly filling a row puts the cursor on the next row explicitly.
	term, _, out = newTestTerminal(t, script("abcdefgh", "\r")...)
	term.sizeFn = func() (int, int) { return 10, 24 }
	if _, err := term.ReadLine(LineOptions{Prompt: "> "}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "> abcdefgh\r\n") {
		t.Errorf("expected forced wrap: %q", out.String())
	}
}

func TestReadLineNoANSIOutputHasNoEscapes(t *testing.T) {
	term, f, out := newTestTerminal(t, script("ab\x1b[DX\x7f\x1b[3~\r")...)
	f.ansi = false
	got, err := term.ReadLine(LineOptions{Prompt: "> "})
	if err != nil || got != "a" {
		t.Fatalf("ReadLine = %q, %v", got, err)
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Errorf("escape sequences written without ANSI support: %q", out.String())
	}
}

func TestReadLineStdoutNotTTY(t *testing.T) {
	f := newFake(script("secret-ish\r")...)
	out := &syncBuffer{}
	term := newTerminal(f, strings.NewReader(""), out, false)
	got, err := term.ReadLine(LineOptions{Prompt: "> "})
	if err != nil || got != "secret-ish" {
		t.Fatalf("ReadLine = %q, %v", got, err)
	}
	if o := out.String(); o != "> " {
		t.Errorf("output = %q, want just the prompt", o)
	}
}

func TestReadLineSuspendResume(t *testing.T) {
	term, f, out := newTestTerminal(t, script("ab", "\x1a", "c\r")...)
	suspended := 0
	term.canSuspend = func() bool { return true }
	term.suspend = func() {
		suspended++
		if term.IsRaw() || f.raw {
			t.Error("terminal still raw while suspended")
		}
	}
	got, err := term.ReadLine(LineOptions{Prompt: "> "})
	if err != nil || got != "abc" {
		t.Fatalf("ReadLine = %q, %v", got, err)
	}
	if suspended != 1 || f.rawCalls != 2 || f.restores != 2 {
		t.Errorf("suspended %d, raw %d, restores %d", suspended, f.rawCalls, f.restores)
	}
	// Bracketed paste must be re-enabled after resume.
	if c := strings.Count(out.String(), "\x1b[?2004h"); c != 2 {
		t.Errorf("paste enabled %d times, want 2", c)
	}
	if term.IsRaw() {
		t.Error("left raw")
	}
}

func TestReadLineCtrlZWithoutJobControl(t *testing.T) {
	term, _, _ := newTestTerminal(t, script("a\x1ab\r")...)
	got, err := term.ReadLine(LineOptions{})
	if err != nil || got != "ab" {
		t.Fatalf("ReadLine = %q, %v", got, err)
	}
}

func TestReadLineNonTTY(t *testing.T) {
	out := &syncBuffer{}
	term := newTerminal(nil, strings.NewReader("  hello world  \nsecond\r\n\nlast"), out, false)
	for _, want := range []string{"hello world", "second", "", "last"} {
		got, err := term.ReadLine(LineOptions{Prompt: "? "})
		if err != nil || got != want {
			t.Fatalf("ReadLine = %q, %v; want %q", got, err, want)
		}
	}
	if got, err := term.ReadLine(LineOptions{}); got != "" || err != io.EOF {
		t.Fatalf("at EOF: %q, %v", got, err)
	}
	if out.String() != "? ? ? ? " {
		t.Errorf("prompts = %q", out.String())
	}
	// Hidden input is just a line too.
	term = newTerminal(nil, strings.NewReader("pw with space \n"), out, false)
	if got, _ := term.ReadLine(LineOptions{Hidden: true, KeepSpace: true}); got != "pw with space " {
		t.Errorf("hidden non-TTY = %q", got)
	}
}

func TestReadLineMinttyHidden(t *testing.T) {
	term := newTerminal(nil, strings.NewReader("visible\nsecret\n"), io.Discard, false)
	term.noHidden = true
	if got, err := term.ReadLine(LineOptions{}); err != nil || got != "visible" {
		t.Fatalf("visible = %q, %v", got, err)
	}
	if _, err := term.ReadLine(LineOptions{Hidden: true}); !errors.Is(err, ErrNoHiddenInput) {
		t.Fatalf("hidden err = %v", err)
	}
	if !strings.Contains(ErrNoHiddenInput.Error(), "winpty pm") {
		t.Error("ErrNoHiddenInput should mention winpty")
	}
}

func TestSanitizePaste(t *testing.T) {
	if got := string(sanitizePaste("a\r\nb\rc\nd\te\x00\x1b\u0085f")); got != "a b c d\tef" {
		t.Errorf("got %q", got)
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[1;32mGreen\x1b[0m \x1b]8;;http://x\x1b\\link\x1b]8;;\x07!"
	if got := stripANSI(in); got != "Green link!" {
		t.Errorf("got %q", got)
	}
}
