package tty

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadKey(t *testing.T) {
	term, f, _ := newTestTerminal(t, script("\x1b[I", "a", "\x1b[1;5A", "\x03")...)
	k, err := term.ReadKey()
	if err != nil || !k.IsRune('a') {
		t.Fatalf("ReadKey = %v, %v; want 'a' (focus event skipped)", k, err)
	}
	k, err = term.ReadKey()
	if err != nil || k.Type != KeyUp || k.Mod != ModCtrl {
		t.Fatalf("ReadKey = %v, %v; want Ctrl+Up", k, err)
	}
	if _, err = term.ReadKey(); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("ReadKey err = %v, want ErrInterrupted", err)
	}
	if _, err = term.ReadKey(); err != io.EOF {
		t.Fatalf("ReadKey at end = %v, want EOF", err)
	}
	if f.rawCalls != 4 || f.restores != 4 || term.IsRaw() {
		t.Errorf("raw %d restores %d", f.rawCalls, f.restores)
	}
}

func TestReadKeyKeepsPendingKeysAcrossCalls(t *testing.T) {
	term, _, _ := newTestTerminal(t, script("ab\x1b[Bc")...)
	var got []Key
	for i := 0; i < 4; i++ {
		k, err := term.ReadKey()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, k)
	}
	want := keysOf(kr('a'), kr('b'), k(KeyDown), kr('c'))
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestReadKeyTimeout(t *testing.T) {
	term, _, _ := newTestTerminal(t, chunk{5 * time.Second, "x"})
	k, ok, err := term.ReadKeyTimeout(100 * time.Millisecond)
	if ok || err != nil {
		t.Fatalf("ReadKeyTimeout = %v, %v, %v; want timeout", k, ok, err)
	}
	k, ok, err = term.ReadKeyTimeout(10 * time.Second)
	if !ok || err != nil || !k.IsRune('x') {
		t.Fatalf("ReadKeyTimeout = %v, %v, %v; want x", k, ok, err)
	}
	if term.IsRaw() {
		t.Error("left raw")
	}
}

func TestNotTerminal(t *testing.T) {
	term := newTerminal(nil, strings.NewReader("abc\n"), io.Discard, false)
	if _, err := term.ReadKey(); err != ErrNotTerminal {
		t.Errorf("ReadKey: %v", err)
	}
	if _, _, err := term.ReadKeyTimeout(time.Millisecond); err != ErrNotTerminal {
		t.Errorf("ReadKeyTimeout: %v", err)
	}
	if _, err := term.EnterRaw(); err != ErrNotTerminal {
		t.Errorf("EnterRaw: %v", err)
	}
	term.Discard() // must not touch the line reader
	if s, _ := term.ReadLine(LineOptions{}); s != "abc" {
		t.Errorf("Discard dropped piped input: %q", s)
	}
}

func TestEnterRawNesting(t *testing.T) {
	term, f, _ := newTestTerminal(t)
	outer, err := term.EnterRaw()
	if err != nil || !term.IsRaw() {
		t.Fatal(err)
	}
	inner, err := term.EnterRaw()
	if err != nil {
		t.Fatal(err)
	}
	inner()
	if !term.IsRaw() || f.restores != 0 {
		t.Fatal("inner restore must be a no-op")
	}
	outer()
	outer()
	if term.IsRaw() || f.rawCalls != 1 || f.restores != 1 {
		t.Fatalf("raw %v calls %d restores %d", term.IsRaw(), f.rawCalls, f.restores)
	}
	// Restore is idempotent and makes a later outer restore harmless.
	outer, _ = term.EnterRaw()
	term.Restore()
	term.Restore()
	outer()
	if f.restores != 2 {
		t.Fatalf("restores %d, want 2", f.restores)
	}
}

func TestRestoreUndoesPasteAndCursor(t *testing.T) {
	term, _, out := newTestTerminal(t)
	if _, err := term.EnterRaw(); err != nil {
		t.Fatal(err)
	}
	term.setPaste(true)
	term.setCursorHidden(true)
	term.Restore()
	o := out.String()
	if !strings.HasSuffix(o, "\x1b[?2004l\x1b[?25h") {
		t.Errorf("output = %q", o)
	}
	term.Restore()
	if out.String() != o {
		t.Error("second Restore wrote again")
	}
}

func TestPrintf(t *testing.T) {
	term, _, out := newTestTerminal(t)
	term.Printf("a\nb\r\n")
	restore, _ := term.EnterRaw()
	term.Printf("c\nd\r\n%d\n", 1)
	restore()
	if got := out.String(); got != "a\nb\r\nc\r\nd\r\n1\r\n" {
		t.Errorf("got %q", got)
	}
}

func TestDiscard(t *testing.T) {
	term, f, _ := newTestTerminal(t, script("ab", "cd", "e")...)
	if k, _ := term.ReadKey(); !k.IsRune('a') {
		t.Fatalf("got %v", k)
	}
	term.Discard() // drops the pending "b" and the queued "cd"
	if f.flushes != 1 {
		t.Errorf("flushes = %d", f.flushes)
	}
	if k, _ := term.ReadKey(); !k.IsRune('e') {
		t.Fatalf("after Discard got %v, want e", k)
	}
}

func TestExitRestores(t *testing.T) {
	old := osExit
	defer func() { osExit = old }()
	code := -1
	osExit = func(c int) { code = c }
	Exit(3)
	if code != 3 {
		t.Errorf("exit code %d", code)
	}
}

func TestKeyString(t *testing.T) {
	for k, want := range map[Key]string{
		{Type: KeyUp, Mod: ModCtrl}:              "Ctrl+Up",
		{Type: KeyRune, Rune: 'x', Mod: ModAlt}:  "Alt+'x'",
		{Type: KeyCtrl, Rune: 'c', Mod: ModCtrl}: "Ctrl(c)",
		{Type: KeyPaste, Paste: "p"}:             `Paste("p")`,
	} {
		if got := k.String(); got != want {
			t.Errorf("%#v.String() = %q, want %q", k, got, want)
		}
	}
}
