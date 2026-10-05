package tty

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// chunk is a piece of input that becomes readable delay after the previous
// read returned.
type chunk struct {
	delay time.Duration
	data  string
}

// fakeConsole replays chunks in virtual time: a Read with a timeout shorter
// than the next chunk's delay returns a timeout immediately (and uses up
// that much of the delay), so timing tests are deterministic. When the
// script is exhausted, reads with a timeout time out and reads without one
// return io.EOF.
type fakeConsole struct {
	mu       sync.Mutex
	chunks   []chunk
	ansi     bool
	rawCalls int
	restores int
	flushes  int
	raw      bool
}

func newFake(chunks ...chunk) *fakeConsole { return &fakeConsole{chunks: chunks, ansi: true} }

// keys builds a script where every string arrives at once, back to back.
func script(parts ...string) []chunk {
	out := make([]chunk, len(parts))
	for i, p := range parts {
		out[i] = chunk{data: p}
	}
	return out
}

func (f *fakeConsole) Read(p []byte, timeout time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.chunks) == 0 {
		if timeout < 0 {
			return 0, io.EOF
		}
		return 0, nil
	}
	c := &f.chunks[0]
	if timeout >= 0 && c.delay > timeout {
		c.delay -= timeout
		return 0, nil
	}
	n := copy(p, c.data)
	if n < len(c.data) {
		c.data = c.data[n:]
		c.delay = 0
	} else {
		f.chunks = f.chunks[1:]
	}
	return n, nil
}

func (f *fakeConsole) makeRaw() (func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rawCalls++
	f.raw = true
	return func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.restores++
		f.raw = false
		return nil
	}, nil
}

func (f *fakeConsole) flushInput() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	if len(f.chunks) > 0 && f.chunks[0].delay == 0 {
		f.chunks = f.chunks[1:]
	}
	return nil
}

func (f *fakeConsole) enableOutputVT() (func(), bool) { return func() {}, f.ansi }

// syncBuffer is a goroutine-safe bytes.Buffer.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newTestTerminal returns an interactive terminal over a fake console.
func newTestTerminal(t *testing.T, chunks ...chunk) (*terminal, *fakeConsole, *syncBuffer) {
	t.Helper()
	f := newFake(chunks...)
	out := &syncBuffer{}
	return newTerminal(f, strings.NewReader(""), out, true), f, out
}

// collectKeys decodes all keys from the fake source until EOF.
func collectKeys(t *testing.T, r *keyReader) []Key {
	t.Helper()
	var keys []Key
	for i := 0; i < 1000; i++ {
		k, ok, err := r.next(time.Time{})
		if err == io.EOF {
			return keys
		}
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if !ok {
			t.Fatalf("next: unexpected timeout")
		}
		keys = append(keys, k)
	}
	t.Fatal("too many keys")
	return nil
}
