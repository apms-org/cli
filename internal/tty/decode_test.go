package tty

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// decodeAll decodes b completely, as the reader does when no more bytes
// arrive: decode without flush while possible, then flush the rest.
func decodeAll(b []byte) []Key {
	var keys []Key
	for len(b) > 0 {
		k, n, ok := decode(b, false)
		if !ok {
			k, n, _ = decode(b, true)
		}
		if n <= 0 {
			panic("no progress")
		}
		b = b[n:]
		if k.Type != KeyIgnore {
			keys = append(keys, k)
		}
	}
	return keys
}

func k(t KeyType) Key            { return Key{Type: t} }
func km(t KeyType, m Mod) Key    { return Key{Type: t, Mod: m} }
func kr(r rune) Key              { return Key{Type: KeyRune, Rune: r} }
func krm(r rune, m Mod) Key      { return Key{Type: KeyRune, Rune: r, Mod: m} }
func kc(r rune) Key              { return Key{Type: KeyCtrl, Rune: r, Mod: ModCtrl} }
func kcm(r rune, m Mod) Key      { return Key{Type: KeyCtrl, Rune: r, Mod: ModCtrl | m} }
func kp(s string) Key            { return Key{Type: KeyPaste, Paste: s} }
func keysOf(ks ...Key) []Key     { return ks }
func none() []Key                { return nil }
func one(t KeyType, m Mod) []Key { return []Key{{Type: t, Mod: m}} }

func TestDecode(t *testing.T) {
	const (
		S = ModShift
		A = ModAlt
		C = ModCtrl
	)
	tests := []struct {
		name string
		in   string
		want []Key
	}{
		// Esc, Enter, Backspace, Tab
		{"esc", "\x1b", keysOf(k(KeyEsc))},
		{"esc esc", "\x1b\x1b", keysOf(k(KeyEsc), k(KeyEsc))},
		{"cr", "\r", keysOf(k(KeyEnter))},
		{"lf", "\n", keysOf(k(KeyEnter))},
		{"crlf is one enter", "\r\n", keysOf(k(KeyEnter))},
		{"cr cr", "\r\r", keysOf(k(KeyEnter), k(KeyEnter))},
		{"crlf crlf", "\r\n\r\n", keysOf(k(KeyEnter), k(KeyEnter))},
		{"keypad enter", "\x1bOM", keysOf(k(KeyEnter))},
		{"del byte", "\x7f", keysOf(k(KeyBackspace))},
		{"bs byte", "\x08", keysOf(k(KeyBackspace))},
		{"tab", "\t", keysOf(k(KeyTab))},
		{"shift tab", "\x1b[Z", one(KeyShiftTab, S)},
		// Delete
		{"delete", "\x1b[3~", keysOf(k(KeyDelete))},
		{"ctrl delete", "\x1b[3;5~", one(KeyDelete, C)},
		{"rxvt shift delete", "\x1b[3$", one(KeyDelete, S)},
		{"rxvt ctrl delete", "\x1b[3^", one(KeyDelete, C)},
		// Arrows
		{"up", "\x1b[A", keysOf(k(KeyUp))},
		{"down", "\x1b[B", keysOf(k(KeyDown))},
		{"right", "\x1b[C", keysOf(k(KeyRight))},
		{"left", "\x1b[D", keysOf(k(KeyLeft))},
		{"app up", "\x1bOA", keysOf(k(KeyUp))},
		{"app down", "\x1bOB", keysOf(k(KeyDown))},
		{"app right", "\x1bOC", keysOf(k(KeyRight))},
		{"app left", "\x1bOD", keysOf(k(KeyLeft))},
		{"ctrl right", "\x1b[1;5C", one(KeyRight, C)},
		{"shift left", "\x1b[1;2D", one(KeyLeft, S)},
		{"alt up", "\x1b[1;3A", one(KeyUp, A)},
		{"ctrl shift alt meta down", "\x1b[1;16B", one(KeyDown, S|A|C|ModMeta)},
		{"rxvt shift up", "\x1b[a", one(KeyUp, S)},
		{"rxvt shift left", "\x1b[d", one(KeyLeft, S)},
		{"rxvt ctrl down", "\x1bOb", one(KeyDown, C)},
		{"rxvt ctrl right", "\x1bOc", one(KeyRight, C)},
		{"esc esc [A is alt up", "\x1b\x1b[A", one(KeyUp, A)},
		{"esc esc OA is alt up", "\x1b\x1bOA", one(KeyUp, A)},
		// Home / End
		{"home H", "\x1b[H", keysOf(k(KeyHome))},
		{"home OH", "\x1bOH", keysOf(k(KeyHome))},
		{"home 1~", "\x1b[1~", keysOf(k(KeyHome))},
		{"home 7~", "\x1b[7~", keysOf(k(KeyHome))},
		{"ctrl home", "\x1b[1;5H", one(KeyHome, C)},
		{"rxvt home $", "\x1b[7$", one(KeyHome, S)},
		{"rxvt home ^", "\x1b[7^", one(KeyHome, C)},
		{"rxvt home @", "\x1b[7@", one(KeyHome, C|S)},
		{"end F", "\x1b[F", keysOf(k(KeyEnd))},
		{"end OF", "\x1bOF", keysOf(k(KeyEnd))},
		{"end 4~", "\x1b[4~", keysOf(k(KeyEnd))},
		{"end 8~", "\x1b[8~", keysOf(k(KeyEnd))},
		{"shift end", "\x1b[1;2F", one(KeyEnd, S)},
		{"rxvt end $", "\x1b[8$", one(KeyEnd, S)},
		{"rxvt end ^", "\x1b[8^", one(KeyEnd, C)},
		{"rxvt end @", "\x1b[8@", one(KeyEnd, C|S)},
		// PgUp / PgDn
		{"pgup", "\x1b[5~", keysOf(k(KeyPgUp))},
		{"pgdn", "\x1b[6~", keysOf(k(KeyPgDn))},
		{"ctrl pgup", "\x1b[5;5~", one(KeyPgUp, C)},
		{"rxvt ctrl pgdn", "\x1b[6^", one(KeyPgDn, C)},
		{"rxvt shift pgup", "\x1b[5$", one(KeyPgUp, S)},
		// Control keys
		{"ctrl c", "\x03", keysOf(kc('c'))},
		{"ctrl d", "\x04", keysOf(kc('d'))},
		{"ctrl u", "\x15", keysOf(kc('u'))},
		{"ctrl w", "\x17", keysOf(kc('w'))},
		{"ctrl z", "\x1a", keysOf(kc('z'))},
		{"ctrl a", "\x01", keysOf(kc('a'))},
		{"ctrl e", "\x05", keysOf(kc('e'))},
		{"ctrl backslash", "\x1c", keysOf(kc('\\'))},
		{"ctrl space ignored", "\x00", none()},
		// Alt
		{"alt j", "\x1bj", keysOf(krm('j', A))},
		{"alt J", "\x1bJ", keysOf(krm('J', A))},
		{"alt utf8", "\x1bé", keysOf(krm('é', A))},
		{"alt backspace", "\x1b\x7f", one(KeyBackspace, A)},
		{"alt ctrl c", "\x1b\x03", keysOf(kcm('c', A))},
		{"alt enter", "\x1b\r", one(KeyEnter, A)},
		// Paste
		{"paste", "\x1b[200~hello\x1b[201~", keysOf(kp("hello"))},
		{"paste with esc", "\x1b[200~a\x1bb\x1b[Ac\x1b[201~", keysOf(kp("a\x1bb\x1b[Ac"))},
		{"paste with newlines", "\x1b[200~a\r\nb\x1b[201~x", keysOf(kp("a\r\nb"), kr('x'))},
		{"empty paste", "\x1b[200~\x1b[201~", keysOf(kp(""))},
		{"unterminated paste", "\x1b[200~abc\x1b[20", keysOf(kp("abc"))},
		{"stray paste end", "\x1b[201~a", keysOf(kr('a'))},
		{"esc then paste", "\x1b\x1b[200~p\x1b[201~", keysOf(k(KeyEsc), kp("p"))},
		// Ignored sequences
		{"focus in", "\x1b[I", none()},
		{"focus out", "\x1b[O", none()},
		{"cursor report", "\x1b[12;40R", none()},
		{"sgr mouse press", "\x1b[<0;10;20M", none()},
		{"sgr mouse release", "\x1b[<0;10;20m", none()},
		{"x10 mouse", "\x1b[M !!x", keysOf(kr('x'))},
		{"da1 reply", "\x1b[?1;2c", none()},
		{"da2 reply", "\x1b[>0;95;0c", none()},
		{"decrpm private $y", "\x1b[?2004;1$yx", keysOf(kr('x'))},
		{"win32 input mode", "\x1b[65;30;97;1;0;1_", none()},
		{"linux console f1", "\x1b[[A", none()},
		{"linux console f5", "\x1b[[E", none()},
		{"ss3 f1", "\x1bOP", none()},
		{"ss3 f4", "\x1bOS", none()},
		{"f1 with mods", "\x1b[1;2P", none()},
		{"f1 11~", "\x1b[11~", none()},
		{"f12 24~", "\x1b[24~", none()},
		{"ctrl f5", "\x1b[15;5~", none()},
		{"insert", "\x1b[2~", none()},
		{"keypad 5", "\x1b[E", none()},
		// kitty and modifyOtherKeys
		{"kitty ctrl a", "\x1b[97;5u", keysOf(kc('a'))},
		{"kitty ctrl c", "\x1b[99;5u", keysOf(kc('c'))},
		{"kitty ctrl shift c", "\x1b[99;6u", keysOf(kcm('c', S))},
		{"kitty enter", "\x1b[13u", keysOf(k(KeyEnter))},
		{"kitty esc", "\x1b[27u", keysOf(k(KeyEsc))},
		{"kitty backspace", "\x1b[127u", keysOf(k(KeyBackspace))},
		{"kitty shift tab", "\x1b[9;2u", one(KeyShiftTab, S)},
		{"kitty shift a", "\x1b[97;2u", keysOf(krm('A', S))},
		{"kitty shifted alt", "\x1b[49:33;2u", keysOf(krm('!', S))},
		{"kitty alt x", "\x1b[120;3u", keysOf(krm('x', A))},
		{"kitty release ignored", "\x1b[97;1:3u", none()},
		{"kitty kp enter", "\x1b[57414u", keysOf(k(KeyEnter))},
		{"kitty private use ignored", "\x1b[57399u", none()},
		{"csi u without params ignored", "\x1b[u", none()},
		{"modifyOtherKeys ctrl c", "\x1b[27;5;99~", keysOf(kc('c'))},
		{"modifyOtherKeys shift enter", "\x1b[27;2;13~", one(KeyEnter, S)},
		{"modifyOtherKeys alt a", "\x1b[27;3;97~", keysOf(krm('a', A))},
		{"modifyOtherKeys ctrl tab", "\x1b[27;5;9~", one(KeyTab, C)},
		// Text
		{"ascii", "abc", keysOf(kr('a'), kr('b'), kr('c'))},
		{"utf8 2 byte", "é", keysOf(kr('é'))},
		{"utf8 3 byte", "日本", keysOf(kr('日'), kr('本'))},
		{"utf8 4 byte", "😀", keysOf(kr('😀'))},
		{"invalid utf8 dropped", "\xffa", keysOf(kr('a'))},
		{"application keypad digit", "\x1bOp\x1bOy", keysOf(kr('0'), kr('9'))},
		// Many keys in one chunk
		{"mixed", "ab\x1b[Ac\r\x1b[3~\x03", keysOf(kr('a'), kr('b'), k(KeyUp), kr('c'), k(KeyEnter), k(KeyDelete), kc('c'))},
		{"ignored then key", "\x1b[Ix", keysOf(kr('x'))},
		// Partial / malformed sequences are never text
		{"partial csi", "\x1b[1;", none()},
		{"partial csi bracket", "\x1b[", none()},
		{"partial ss3", "\x1bO", none()},
		{"partial ss3 params", "\x1bO5", none()},
		{"csi broken by control", "\x1b[1\x03", keysOf(kc('c'))},
		{"csi broken by esc", "\x1b[1\x1b[B", keysOf(k(KeyDown))},
		{"overlong csi", "\x1b[" + strings.Repeat("1", 100) + "~x", keysOf(kr('x'))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeAll([]byte(tt.in))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decode(%q)\n got %v\nwant %v", tt.in, got, tt.want)
			}
		})
	}
}

// Every complete sequence must decode without flush (i.e. without waiting
// for the Esc timeout).
func TestDecodeCompleteWithoutFlush(t *testing.T) {
	for _, in := range []string{
		"\x1b[A", "\x1bOA", "\x1b[1;5C", "\x1b[3~", "\x1b[3$", "\x1b[7@", "\x1b[a",
		"\x1b[Z", "\x1b[200~x\x1b[201~", "\x1b[[A", "\x1b[97;5u", "\x1b[27;5;99~",
		"\x1bj", "\x1b\x1b[A", "\x1b[I", "é", "\x1b[<0;1;1M",
	} {
		k, n, ok := decode([]byte(in), false)
		if !ok || n != len(in) {
			t.Errorf("decode(%q, false) = %v, %d, %v; want complete", in, k, n, ok)
		}
	}
	for _, in := range []string{"\x1b", "\x1b[", "\x1b[1;5", "\x1bO", "\x1b[200~abc", "\xe6\x97", "\x1b\x1b", "\x1b\xc3", "\x1b[[", "\x1b[M a"} {
		if k, n, ok := decode([]byte(in), false); ok {
			t.Errorf("decode(%q, false) = %v, %d, true; want need-more", in, k, n)
		}
	}
}

func TestReaderTiming(t *testing.T) {
	ms := time.Millisecond
	tests := []struct {
		name   string
		chunks []chunk
		want   []Key
	}{
		{"esc then [A 10ms later is Up", []chunk{{0, "\x1b"}, {10 * ms, "[A"}}, keysOf(k(KeyUp))},
		{"esc, timeout, j", []chunk{{0, "\x1b"}, {100 * ms, "j"}}, keysOf(k(KeyEsc), kr('j'))},
		{"lone esc then nothing", []chunk{{0, "\x1b"}}, keysOf(k(KeyEsc))},
		{"esc j same chunk is alt j", []chunk{{0, "\x1bj"}}, keysOf(krm('j', ModAlt))},
		{"esc esc[A split", []chunk{{0, "\x1b"}, {10 * ms, "\x1b[A"}}, keysOf(km(KeyUp, ModAlt))},
		{"csi split at every byte", []chunk{{0, "\x1b"}, {5 * ms, "["}, {5 * ms, "1"}, {5 * ms, ";"}, {5 * ms, "5"}, {5 * ms, "D"}}, keysOf(km(KeyLeft, ModCtrl))},
		{"partial csi then timeout is ignored", []chunk{{0, "\x1b[1;"}, {100 * ms, "x"}}, keysOf(kr('x'))},
		{"partial ss3 then timeout is ignored", []chunk{{0, "\x1bO"}, {100 * ms, "x"}}, keysOf(kr('x'))},
		{"utf8 split", []chunk{{0, "\xc3"}, {10 * ms, "\xa9"}}, keysOf(kr('é'))},
		{"utf8 3 byte split twice", []chunk{{0, "\xe6"}, {5 * ms, "\x97"}, {5 * ms, "\xa5x"}}, keysOf(kr('日'), kr('x'))},
		{"emoji split", []chunk{{0, "\xf0\x9f"}, {5 * ms, "\x98\x80"}}, keysOf(kr('😀'))},
		{"paste in several chunks", []chunk{{0, "\x1b[200~hel"}, {500 * ms, "lo wor"}, {time.Second, "ld\x1b[201~"}}, keysOf(kp("hello world"))},
		{"paste with esc in chunks", []chunk{{0, "\x1b[200~a\x1b"}, {300 * ms, "b"}, {10 * ms, "\x1b[201~"}}, keysOf(kp("a\x1bb"))},
		{"paste end marker split", []chunk{{0, "\x1b[200~abc\x1b[20"}, {10 * ms, "1~x"}}, keysOf(kp("abc"), kr('x'))},
		{"paste start split", []chunk{{0, "\x1b[20"}, {10 * ms, "0~abc\x1b[201~"}}, keysOf(kp("abc"))},
		{"paste idle timeout", []chunk{{0, "\x1b[200~abc"}, {3 * time.Second, "x"}}, keysOf(kp("abc"), kr('x'))},
		{"cr then lf in next read is one enter", []chunk{{0, "\r"}, {5 * ms, "\na"}}, keysOf(k(KeyEnter), kr('a'))},
		{"cr a lf", []chunk{{0, "\ra\n"}}, keysOf(k(KeyEnter), kr('a'), k(KeyEnter))},
		{"many keys one read", []chunk{{0, "hello\r"}}, keysOf(kr('h'), kr('e'), kr('l'), kr('l'), kr('o'), k(KeyEnter))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newKeyReader(newFake(tt.chunks...), 50*ms)
			got := collectKeys(t, r)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestReaderPasteCap(t *testing.T) {
	big := strings.Repeat("x", 30)
	r := newKeyReader(newFake(chunk{0, "\x1b[200~" + big}, chunk{10 * time.Millisecond, big + "\x1b[201~z"}), 50*time.Millisecond)
	r.pasteCap = 10
	got := collectKeys(t, r)
	want := keysOf(kp(strings.Repeat("x", 10)), kr('z'))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestReaderDeadline(t *testing.T) {
	r := newKeyReader(newFake(chunk{5 * time.Second, "a"}), 50*time.Millisecond)
	if k, ok, err := r.next(time.Now().Add(20 * time.Millisecond)); ok || err != nil {
		t.Fatalf("next = %v, %v, %v; want timeout", k, ok, err)
	}
	// Pending partial sequence survives a deadline.
	r = newKeyReader(newFake(chunk{0, "\x1b["}, chunk{10 * time.Millisecond, "B"}), 50*time.Millisecond)
	if _, ok, _ := r.next(time.Now()); ok {
		t.Fatal("expected timeout with a zero deadline")
	}
	k, ok, err := r.next(time.Time{})
	if !ok || err != nil || k.Type != KeyDown {
		t.Fatalf("next = %v, %v, %v; want Down", k, ok, err)
	}
}

func TestEscTimeoutFromEnv(t *testing.T) {
	t.Setenv("APM_ESC_TIMEOUT_MS", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CONNECTION", "")
	if got := escTimeoutFromEnv(); got != 50*time.Millisecond {
		t.Errorf("default = %v", got)
	}
	t.Setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
	if got := escTimeoutFromEnv(); got != 150*time.Millisecond {
		t.Errorf("ssh = %v", got)
	}
	t.Setenv("APM_ESC_TIMEOUT_MS", "300")
	if got := escTimeoutFromEnv(); got != 300*time.Millisecond {
		t.Errorf("override = %v", got)
	}
	t.Setenv("APM_ESC_TIMEOUT_MS", "junk")
	if got := escTimeoutFromEnv(); got != 150*time.Millisecond {
		t.Errorf("bad override = %v", got)
	}
}
