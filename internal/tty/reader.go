package tty

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"time"
)

// source is a raw byte source: the terminal, or a script in tests.
type source interface {
	// Read waits up to timeout for input and reads what is available into
	// p. timeout < 0 waits forever; timeout == 0 polls. It returns (0, nil)
	// when the timeout expires with no input, and io.EOF when the input is
	// closed. n > 0 implies err == nil.
	Read(p []byte, timeout time.Duration) (n int, err error)
}

const (
	defaultEscTimeout = 50 * time.Millisecond
	sshEscTimeout     = 150 * time.Millisecond
	pasteIdleTimeout  = 2 * time.Second
	pasteCap          = 1 << 20 // 1 MiB
)

// escTimeoutFromEnv returns how long to wait after an ESC (or an incomplete
// escape sequence) for the rest of the sequence.
func escTimeoutFromEnv() time.Duration {
	if v := os.Getenv("APM_ESC_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 10000 {
			return time.Duration(n) * time.Millisecond
		}
	}
	if os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CONNECTION") != "" {
		return sshEscTimeout
	}
	return defaultEscTimeout
}

// keyReader turns a byte source into keys. It keeps a pending buffer so
// that many keys arriving in one read are returned one at a time and no
// byte is ever dropped, and it resolves ESC-vs-sequence ambiguity with
// timeouts.
type keyReader struct {
	src          source
	escTimeout   time.Duration
	pasteTimeout time.Duration
	pasteCap     int

	buf       []byte
	afterCR   bool // last key was a bare CR: swallow an immediately following LF
	skipPaste bool // paste exceeded pasteCap: drop bytes up to the end marker
	eof       bool
	rbuf      [4096]byte
}

func newKeyReader(src source, escTimeout time.Duration) *keyReader {
	return &keyReader{src: src, escTimeout: escTimeout, pasteTimeout: pasteIdleTimeout, pasteCap: pasteCap}
}

// reset drops all pending input and state.
func (r *keyReader) reset() {
	r.buf = nil
	r.afterCR = false
	r.skipPaste = false
	r.eof = false
}

func (r *keyReader) consume(n int) {
	r.buf = r.buf[n:]
	if len(r.buf) == 0 {
		r.buf = nil
	}
}

// fill reads once from the source with the given timeout.
func (r *keyReader) fill(timeout time.Duration) (int, error) {
	n, err := r.src.Read(r.rbuf[:], timeout)
	if n > 0 {
		r.buf = append(r.buf, r.rbuf[:n]...)
		return n, nil
	}
	return 0, err
}

// next returns the next key, skipping KeyIgnore. A zero deadline waits
// forever; otherwise ok=false is returned once the deadline passes with no
// complete key. Pending bytes are kept across calls.
func (r *keyReader) next(deadline time.Time) (Key, bool, error) {
	for {
		if r.skipPaste {
			if i := bytes.Index(r.buf, []byte(pasteEnd)); i >= 0 {
				r.consume(i + len(pasteEnd))
				r.skipPaste = false
				continue
			}
			// Keep a possible partial end marker.
			if keep := len(pasteEnd) - 1; len(r.buf) > keep {
				r.buf = append([]byte(nil), r.buf[len(r.buf)-keep:]...)
			}
		} else if len(r.buf) > 0 {
			if r.afterCR && r.buf[0] == '\n' {
				r.afterCR = false
				r.consume(1)
				continue
			}
			k, n, ok := decode(r.buf, r.eof)
			if !ok && bytes.HasPrefix(r.buf, []byte(pasteStart)) && len(r.buf)-len(pasteStart) > r.pasteCap {
				// Oversized paste: deliver the first pasteCap bytes and
				// discard the rest of it.
				k = Key{Type: KeyPaste, Paste: string(r.buf[len(pasteStart) : len(pasteStart)+r.pasteCap])}
				n, ok = len(r.buf), true
				r.skipPaste = true
			}
			if ok {
				if k, ok := r.take(k, n); ok {
					return k, true, nil
				}
				continue
			}
		}
		if r.eof {
			if r.skipPaste {
				r.reset()
				r.eof = true
			}
			return Key{}, false, io.EOF
		}

		// Need more bytes. When a sequence (or paste) is incomplete, wait
		// at most its timeout; then decode what we have with flush=true.
		wait := time.Duration(-1)
		seqWait := false
		if len(r.buf) > 0 || r.skipPaste {
			wait, seqWait = r.escTimeout, true
			if r.skipPaste || bytes.HasPrefix(r.buf, []byte(pasteStart)) {
				wait = r.pasteTimeout
			}
		}
		if !deadline.IsZero() {
			rem := time.Until(deadline)
			if rem < 0 {
				rem = 0
			}
			if wait < 0 || rem < wait {
				wait, seqWait = rem, false
			}
		}
		n, err := r.fill(wait)
		if n > 0 {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				r.eof = true
				continue
			}
			return Key{}, false, err
		}
		if !seqWait {
			return Key{}, false, nil // deadline
		}
		if r.skipPaste {
			r.skipPaste = false
			r.buf = nil
			continue
		}
		k, n, _ := decode(r.buf, true)
		if k, ok := r.take(k, n); ok {
			return k, true, nil
		}
	}
}

// take consumes n bytes for key k and reports whether k should be returned.
func (r *keyReader) take(k Key, n int) (Key, bool) {
	if n <= 0 { // defensive: never loop without progress
		n = 1
	}
	r.afterCR = n == 1 && r.buf[0] == '\r'
	r.consume(n)
	return k, k.Type != KeyIgnore
}
