package tty

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	pasteStart = "\x1b[200~"
	pasteEnd   = "\x1b[201~"
	// maxSeqLen bounds the parameters of an SS3 sequence.
	maxSeqLen = 64
	// maxJunkLen bounds an unterminated CSI sequence we keep waiting for.
	maxJunkLen = 4096
)

var ignoreKey = Key{Type: KeyIgnore}

// decode decodes the first key in b.
//
// It returns the key, the number of bytes it used and ok=true, or ok=false
// when b is a prefix of something longer and more bytes are needed. With
// flush=true (no more bytes are coming soon) it never asks for more: a bare
// ESC becomes KeyEsc, an incomplete escape sequence becomes KeyIgnore (it is
// never turned into text), an unterminated bracketed paste is delivered as
// is. decode is pure; it keeps no state between calls.
func decode(b []byte, flush bool) (Key, int, bool) {
	if len(b) == 0 {
		return Key{}, 0, false
	}
	c := b[0]
	switch {
	case c == 0x1b:
		return decodeEsc(b, flush)
	case c == '\r':
		if len(b) > 1 && b[1] == '\n' {
			return Key{Type: KeyEnter}, 2, true
		}
		return Key{Type: KeyEnter}, 1, true
	case c < 0x20 || c == 0x7f:
		return controlKey(c), 1, true
	case c < 0x80:
		return Key{Type: KeyRune, Rune: rune(c)}, 1, true
	}
	if !utf8.FullRune(b) {
		if !flush {
			return Key{}, 0, false
		}
		return ignoreKey, 1, true
	}
	r, size := utf8.DecodeRune(b)
	if r == utf8.RuneError && size <= 1 {
		return ignoreKey, 1, true
	}
	return Key{Type: KeyRune, Rune: r}, size, true
}

// controlKey maps a C0 control byte (other than ESC) or DEL to a key.
func controlKey(c byte) Key {
	switch c {
	case 0x00: // Ctrl+Space / Ctrl+@
		return ignoreKey
	case 0x08, 0x7f:
		return Key{Type: KeyBackspace}
	case 0x09:
		return Key{Type: KeyTab}
	case 0x0a, 0x0d:
		return Key{Type: KeyEnter}
	case 0x1b:
		return Key{Type: KeyEsc}
	}
	if c >= 0x01 && c <= 0x1a {
		return Key{Type: KeyCtrl, Rune: rune('a' + c - 1), Mod: ModCtrl}
	}
	if c >= 0x1c && c <= 0x1f { // Ctrl+\ Ctrl+] Ctrl+^ Ctrl+_
		return Key{Type: KeyCtrl, Rune: rune(c + 0x40), Mod: ModCtrl}
	}
	return ignoreKey
}

func decodeEsc(b []byte, flush bool) (Key, int, bool) {
	if len(b) == 1 {
		if flush {
			return Key{Type: KeyEsc}, 1, true
		}
		return Key{}, 0, false
	}
	switch c := b[1]; {
	case c == '[':
		return decodeCSI(b, flush)
	case c == 'O':
		return decodeSS3(b, flush)
	case c == 0x1b:
		// ESC ESC: either Alt + an escape sequence (rxvt/xterm send
		// ESC ESC [A for Alt+Up) or two Esc presses.
		if len(b) == 2 {
			if flush {
				return Key{Type: KeyEsc}, 1, true
			}
			return Key{}, 0, false
		}
		if b[2] != '[' && b[2] != 'O' || bytes.HasPrefix(b[1:], []byte(pasteStart)) {
			return Key{Type: KeyEsc}, 1, true
		}
		k, n, ok := decodeEsc(b[1:], flush)
		if !ok {
			return Key{}, 0, false
		}
		if k.Type != KeyIgnore {
			k.Mod |= ModAlt
		}
		return k, n + 1, true
	case c < 0x20 || c == 0x7f:
		k := controlKey(c)
		if k.Type == KeyIgnore {
			return ignoreKey, 2, true
		}
		k.Mod |= ModAlt
		return k, 2, true
	case c < 0x80:
		return Key{Type: KeyRune, Rune: rune(c), Mod: ModAlt}, 2, true
	}
	rest := b[1:]
	if !utf8.FullRune(rest) {
		if !flush {
			return Key{}, 0, false
		}
		return Key{Type: KeyEsc}, 1, true
	}
	r, size := utf8.DecodeRune(rest)
	if r == utf8.RuneError && size <= 1 {
		return Key{Type: KeyEsc}, 1, true
	}
	return Key{Type: KeyRune, Rune: r, Mod: ModAlt}, 1 + size, true
}

// decodeSS3 handles ESC O <params> <final>.
func decodeSS3(b []byte, flush bool) (Key, int, bool) {
	i := 2
	for i < len(b) && i < maxSeqLen && (b[i] >= '0' && b[i] <= '9' || b[i] == ';') {
		i++
	}
	if i >= len(b) {
		if flush {
			return ignoreKey, len(b), true
		}
		return Key{}, 0, false
	}
	f := b[i]
	if f < 0x40 || f > 0x7e {
		return ignoreKey, i, true // malformed; drop what we have
	}
	var mod Mod
	if i > 2 {
		fields := strings.Split(string(b[2:i]), ";")
		mod = modParam(fields[len(fields)-1])
	}
	n := i + 1
	switch f {
	case 'A', 'B', 'C', 'D':
		return Key{Type: arrowType(f), Mod: mod}, n, true
	case 'a', 'b', 'c', 'd': // rxvt Ctrl+arrows
		return Key{Type: arrowType(f - 'a' + 'A'), Mod: mod | ModCtrl}, n, true
	case 'H':
		return Key{Type: KeyHome, Mod: mod}, n, true
	case 'F':
		return Key{Type: KeyEnd, Mod: mod}, n, true
	case 'M': // keypad Enter
		return Key{Type: KeyEnter, Mod: mod}, n, true
	case 'Z':
		return Key{Type: KeyShiftTab, Mod: mod | ModShift}, n, true
	}
	// Application keypad mode.
	if r, ok := ss3Keypad[f]; ok {
		return Key{Type: KeyRune, Rune: r}, n, true
	}
	return ignoreKey, n, true // F1-F4 (P-S) and friends
}

var ss3Keypad = map[byte]rune{
	'p': '0', 'q': '1', 'r': '2', 's': '3', 't': '4', 'u': '5', 'v': '6',
	'w': '7', 'x': '8', 'y': '9', 'j': '*', 'k': '+', 'l': ',', 'm': '-',
	'n': '.', 'o': '/', 'X': '=',
}

func arrowType(f byte) KeyType {
	switch f {
	case 'A':
		return KeyUp
	case 'B':
		return KeyDown
	case 'C':
		return KeyRight
	}
	return KeyLeft
}

// decodeCSI handles ESC [ ...
func decodeCSI(b []byte, flush bool) (Key, int, bool) {
	if len(b) == 2 {
		if flush {
			return ignoreKey, 2, true
		}
		return Key{}, 0, false
	}
	if bytes.HasPrefix(b, []byte(pasteStart)) {
		return decodePaste(b, flush)
	}
	switch b[2] {
	case '[': // Linux console F1-F5: ESC [ [ A..E
		if len(b) < 4 {
			if flush {
				return ignoreKey, len(b), true
			}
			return Key{}, 0, false
		}
		return ignoreKey, 4, true
	case 'M': // X10 mouse: ESC [ M Cb Cx Cy (raw bytes)
		if len(b) < 6 {
			if flush {
				return ignoreKey, len(b), true
			}
			return Key{}, 0, false
		}
		return ignoreKey, 6, true
	}
	private := b[2] == '<' || b[2] == '=' || b[2] == '>' || b[2] == '?'
	for i := 2; i < len(b); i++ {
		c := b[i]
		if (c == '$' && !private) || (c >= 0x40 && c <= 0x7e) {
			// '$' is rxvt's Shift final byte (ESC [ 3 $). A strict parser
			// treats it as an intermediate and hangs waiting for a final.
			if private {
				return ignoreKey, i + 1, true
			}
			return csiKey(string(b[2:i]), c), i + 1, true
		}
		if c < 0x20 || c > 0x7e {
			// Not part of a CSI sequence: drop the junk prefix and let the
			// byte be decoded on its own (it may start the next key).
			return ignoreKey, i, true
		}
	}
	// Incomplete. Real sequences are short; give up on runaway junk.
	if flush || len(b) > maxJunkLen {
		return ignoreKey, len(b), true
	}
	return Key{}, 0, false
}

func decodePaste(b []byte, flush bool) (Key, int, bool) {
	rest := b[len(pasteStart):]
	if i := bytes.Index(rest, []byte(pasteEnd)); i >= 0 {
		return Key{Type: KeyPaste, Paste: string(rest[:i])}, len(pasteStart) + i + len(pasteEnd), true
	}
	if !flush {
		return Key{}, 0, false
	}
	// Unterminated: deliver what arrived, minus a partial end marker.
	for j := len(pasteEnd) - 1; j > 0; j-- {
		if bytes.HasSuffix(rest, []byte(pasteEnd[:j])) {
			rest = rest[:len(rest)-j]
			break
		}
	}
	return Key{Type: KeyPaste, Paste: string(rest)}, len(b), true
}

// modParam decodes an xterm modifier parameter: 1 + Shift(1) + Alt(2) +
// Ctrl(4) + Meta(8). kitty adds Hyper(16), Meta(32), CapsLock(64) and
// NumLock(128); lock keys are ignored. Sub-parameters (kitty "mods:event")
// are ignored.
func modParam(s string) Mod {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	m, err := strconv.Atoi(s)
	if err != nil || m <= 1 {
		return 0
	}
	bits := m - 1
	var mod Mod
	if bits&1 != 0 {
		mod |= ModShift
	}
	if bits&2 != 0 {
		mod |= ModAlt
	}
	if bits&4 != 0 {
		mod |= ModCtrl
	}
	if bits&(8|32) != 0 {
		mod |= ModMeta
	}
	return mod
}

// num returns the first sub-parameter of field i as an int, or def.
func num(fields []string, i, def int) int {
	if i >= len(fields) {
		return def
	}
	s := fields[i]
	if j := strings.IndexByte(s, ':'); j >= 0 {
		s = s[:j]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// csiKey interprets a complete, non-private CSI sequence.
func csiKey(params string, final byte) Key {
	// Intermediate bytes (0x20-0x2F) only appear in sequences we ignore.
	if strings.IndexFunc(params, func(r rune) bool { return r < 0x30 }) >= 0 {
		return ignoreKey
	}
	fields := strings.Split(params, ";")
	var mod Mod
	if len(fields) >= 2 {
		mod = modParam(fields[1])
	}
	switch final {
	case 'A', 'B', 'C', 'D':
		if len(fields) == 1 && num(fields, 0, 1) > 1 {
			mod = modParam(fields[0]) // old form: ESC [ 5 A
		}
		return Key{Type: arrowType(final), Mod: mod}
	case 'a', 'b', 'c', 'd': // rxvt Shift+arrows
		if params != "" {
			return ignoreKey
		}
		return Key{Type: arrowType(final - 'a' + 'A'), Mod: ModShift}
	case 'H':
		return Key{Type: KeyHome, Mod: mod}
	case 'F':
		return Key{Type: KeyEnd, Mod: mod}
	case 'Z':
		return Key{Type: KeyShiftTab, Mod: mod | ModShift}
	case '~', '^', '$', '@':
		n := num(fields, 0, 0)
		switch final {
		case '^': // rxvt Ctrl
			mod |= ModCtrl
		case '$': // rxvt Shift
			mod |= ModShift
		case '@': // rxvt Ctrl+Shift
			mod |= ModCtrl | ModShift
		}
		switch n {
		case 1, 7:
			return Key{Type: KeyHome, Mod: mod}
		case 4, 8:
			return Key{Type: KeyEnd, Mod: mod}
		case 3:
			return Key{Type: KeyDelete, Mod: mod}
		case 5:
			return Key{Type: KeyPgUp, Mod: mod}
		case 6:
			return Key{Type: KeyPgDn, Mod: mod}
		case 27: // xterm modifyOtherKeys: CSI 27 ; mods ; code ~
			if final == '~' && len(fields) >= 3 {
				return keyFromCode(num(fields, 2, 0), 0, modParam(fields[1]))
			}
		}
		return ignoreKey // Insert, F-keys (11-24~), stray paste end (201~), ...
	case 'u': // kitty: CSI code[:shifted[:base]] [; mods[:event] [; text]] u
		if params == "" {
			return ignoreKey
		}
		if len(fields) >= 2 {
			if sub := strings.Split(fields[1], ":"); len(sub) >= 2 && sub[1] == "3" {
				return ignoreKey // key release
			}
		}
		codes := strings.Split(fields[0], ":")
		code, err := strconv.Atoi(codes[0])
		if err != nil {
			return ignoreKey
		}
		shifted := 0
		if len(codes) >= 2 && codes[1] != "" {
			shifted, _ = strconv.Atoi(codes[1])
		}
		return keyFromCode(code, rune(shifted), mod)
	}
	// I/O focus, R cursor report (and F3 with modifiers), _ win32-input-mode,
	// P/Q/S F1-F4 with modifiers, E keypad 5, ...
	return ignoreKey
}

// keyFromCode maps a Unicode key code (kitty / modifyOtherKeys) to a Key.
func keyFromCode(code int, shifted rune, mod Mod) Key {
	switch code {
	case 13, 57414: // Enter, kitty KP_Enter
		return Key{Type: KeyEnter, Mod: mod}
	case 9:
		if mod&ModShift != 0 {
			return Key{Type: KeyShiftTab, Mod: mod}
		}
		return Key{Type: KeyTab, Mod: mod}
	case 27:
		return Key{Type: KeyEsc, Mod: mod}
	case 127, 8:
		return Key{Type: KeyBackspace, Mod: mod}
	}
	if code <= 0 || code > utf8.MaxRune || (code >= 0xe000 && code <= 0xf8ff) || code >= 0xf0000 {
		return ignoreKey // invalid or kitty private-use functional key
	}
	if code < 0x20 {
		k := controlKey(byte(code))
		if k.Type != KeyIgnore {
			k.Mod |= mod
		}
		return k
	}
	r := rune(code)
	if mod&ModCtrl != 0 {
		lr := r | 0x20
		if lr >= 'a' && lr <= 'z' && r < 0x80 {
			return Key{Type: KeyCtrl, Rune: lr, Mod: mod}
		}
	}
	if mod&ModShift != 0 {
		if shifted > 0 {
			r = shifted
		} else if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
	}
	return Key{Type: KeyRune, Rune: r, Mod: mod}
}
