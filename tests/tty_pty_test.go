//go:build darwin || linux

package apm_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests drive pm in a real pseudo-terminal, the way a person would, to
// check that keys (Esc above all) do what the screens say and that pm always
// hands the terminal back in cooked mode.

const ptyMasterPassword = "ValidPass123!"

type ptyEnv struct {
	dir   string
	pm    string
	vault string
	base  []string
	n     int
}

func newPTYEnv(t *testing.T) *ptyEnv {
	t.Helper()
	dir := t.TempDir()
	e := &ptyEnv{dir: dir, pm: filepath.Join(dir, "pm"), vault: filepath.Join(dir, "vault", "vault.dat")}
	buildPMBinary(t, e.pm)
	for _, sub := range []string{"home", "tmp", "vault", "config", "data", "state", "cache"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "HOME", "TMPDIR", "TERM", "APM_SESSION_ID", "APM_EPHEMERAL_ID", "APM_VAULT_PATH", "APM_STATE_DIR",
			"APM_ACTOR", "APM_CONTEXT", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
			"APM_ESC_TIMEOUT_MS", "SSH_TTY", "SSH_CONNECTION":
			continue
		}
		e.base = append(e.base, kv)
	}
	e.base = append(e.base,
		"HOME="+filepath.Join(dir, "home"),
		"TMPDIR="+filepath.Join(dir, "tmp"),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
		"XDG_STATE_HOME="+filepath.Join(dir, "state"),
		"XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"TERM=xterm-256color",
		"APM_DESKTOP_NO_TOUCHID=1",
		"APM_ICONS_OFFLINE=1",
	)
	return e
}

// env gives each pm run its own session id, so every run asks for the
// master password instead of reusing a session.
func (e *ptyEnv) env() []string {
	e.n++
	return append(append([]string(nil), e.base...), "APM_SESSION_ID=ptytest"+strconv.Itoa(e.n)+strconv.FormatInt(time.Now().UnixNano(), 10))
}

func (e *ptyEnv) run(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(e.pm, append([]string{"--vault", e.vault}, args...)...)
	cmd.Env = e.env()
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pm %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (e *ptyEnv) setup(t *testing.T, logins ...string) {
	t.Helper()
	if out := e.run(t, ptyMasterPassword+"\n", "setup", "--non-interactive"); !strings.Contains(out, "Setup completed successfully.") {
		t.Fatalf("setup failed:\n%s", out)
	}
	for _, name := range logins {
		if out := e.run(t, ptyMasterPassword+"\n"+name+"\n"+name+"_user\n\n", "add", "PASSWORD"); !strings.Contains(out, "Entry saved.") {
			t.Fatalf("add %s failed:\n%s", name, out)
		}
	}
}

type ptyProc struct {
	t      *testing.T
	cmd    *exec.Cmd
	master *os.File
	slave  *os.File

	mu   sync.Mutex
	out  []byte
	done chan struct{}
	code int
}

func (e *ptyEnv) start(t *testing.T, args ...string) *ptyProc {
	t.Helper()
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	sfd := int(slave.Fd())
	if err := unix.IoctlSetWinsize(sfd, unix.TIOCSWINSZ, &unix.Winsize{Row: 50, Col: 140}); err != nil {
		t.Fatalf("set window size: %v", err)
	}
	// A shell owns the terminal and prints its settings before and after pm,
	// so the test sees the mode pm leaves behind.
	script := `stty -a; echo ` + sttyBefore + `; "$@"; code=$?; echo ` + sttyAfter + `; stty -a; exit $code`
	cmd := exec.Command("/bin/sh", append([]string{"-c", script, "sh", e.pm, "--vault", e.vault}, args...)...)
	cmd.Env = e.env()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start pm: %v", err)
	}
	p := &ptyProc{t: t, cmd: cmd, master: master, slave: slave, done: make(chan struct{})}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.out = append(p.out, buf[:n]...)
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			p.code = ee.ExitCode()
		} else if err != nil {
			p.code = -1
		}
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = cmd.Process.Kill()
			<-p.done
		}
		master.Close()
		slave.Close()
	})
	return p
}

func (p *ptyProc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.out)
}

func (p *ptyProc) mark() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.out)
}

func (p *ptyProc) send(s string) {
	p.t.Helper()
	if _, err := p.master.Write([]byte(s)); err != nil {
		p.t.Fatalf("write to pty: %v", err)
	}
}

func (p *ptyProc) fail(format string, args ...any) {
	p.t.Helper()
	out := p.output()
	if len(out) > 6000 {
		out = "..." + out[len(out)-6000:]
	}
	args = append(args, out)
	p.t.Fatalf(format+"\n--- pty output ---\n%q", args...)
}

// waitFor waits until substr appears in the output after from.
func (p *ptyProc) waitFor(substr string, from int) {
	p.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if out := p.output(); len(out) >= from && strings.Contains(out[from:], substr) {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	p.fail("timed out waiting for %q", substr)
}

const clearScreen = "\x1b[H\x1b[J"

// frame waits for the next complete `pm get` screen drawn after from that
// satisfies ok, and returns it.
func (p *ptyProc) frame(from int, desc string, ok func(string) bool) string {
	p.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out := p.output()
		if len(out) >= from {
			chunks := strings.Split(out[from:], clearScreen)
			for i := len(chunks) - 1; i >= 1; i-- {
				f := chunks[i]
				complete := strings.Contains(f, ": Exit\r\n") || strings.Contains(f, ": Focus Search\r\n")
				if complete && ok(f) {
					return f
				}
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	p.fail("timed out waiting for a screen where %s", desc)
	return ""
}

func searchFocus(f string) bool { return strings.Contains(f, ": Exit\r\n") }
func listFocus(f string) bool   { return strings.Contains(f, ": Focus Search\r\n") }

// selectedLine returns the highlighted row of a `pm get` screen.
func selectedLine(f string) string {
	i := strings.Index(f, "\x1b[1;7m ")
	if i < 0 {
		return ""
	}
	rest := f[i+len("\x1b[1;7m "):]
	if j := strings.Index(rest, " \x1b[0m"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func (p *ptyProc) waitExit() int {
	p.t.Helper()
	select {
	case <-p.done:
		return p.code
	case <-time.After(15 * time.Second):
		p.fail("pm did not exit")
	}
	return 0
}

const (
	sttyBefore = "@@PM-START@@"
	sttyAfter  = "@@PM-END@@"
)

// sections splits the output into the settings before pm, what pm printed
// and the settings after it.
func (p *ptyProc) sections() (before, pm, after string) {
	out := p.output()
	b := strings.Index(out, sttyBefore)
	a := strings.LastIndex(out, sttyAfter)
	if b < 0 || a < b {
		p.fail("missing terminal settings markers")
	}
	return out[:b], out[b+len(sttyBefore) : a], out[a+len(sttyAfter):]
}

// assertCooked checks pm left the terminal in the mode it found it in.
func (p *ptyProc) assertCooked() {
	p.t.Helper()
	p.waitFor(sttyAfter, 0)
	p.waitFor("speed", strings.LastIndex(p.output(), sttyAfter))
	time.Sleep(100 * time.Millisecond) // let the rest of stty's output arrive
	before, _, after := p.sections()
	flags := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, f := range strings.Fields(strings.NewReplacer(";", " ", ":", " ").Replace(s)) {
			m[f] = true
		}
		return m
	}
	fb, fa := flags(before), flags(after)
	for _, f := range []string{"icanon", "echo", "isig", "icrnl", "opost"} {
		if !fa[f] || fa["-"+f] {
			p.fail("terminal left without %s:\n%s", f, after)
		}
	}
	for f := range fb {
		if strings.HasPrefix(f, "-") && !fa[f] || !strings.HasPrefix(f, "-") && fa["-"+f] {
			p.fail("terminal setting %s changed:\nbefore:\n%s\nafter:\n%s", f, before, after)
		}
	}
}

func (p *ptyProc) assertNoCaretEscape() {
	p.t.Helper()
	if _, pm, _ := p.sections(); strings.Contains(pm, "^[") {
		p.fail("output contains a literal ^[")
	}
}

func TestPTY_GetKeys(t *testing.T) {
	e := newPTYEnv(t)
	e.setup(t, "alpha_site", "bravo_site")

	p := e.start(t, "get")
	p.waitFor("Master Password", 0)
	p.send(ptyMasterPassword + "\r")
	first := p.frame(0, "both logins are listed", func(f string) bool {
		return searchFocus(f) && strings.Contains(f, "alpha_site") && strings.Contains(f, "bravo_site")
	})
	sel1 := selectedLine(first)
	if sel1 == "" {
		p.fail("no highlighted row in the first screen")
	}

	// Down moves the selection.
	m := p.mark()
	p.send("\x1b[B")
	f := p.frame(m, "the selection moved down", func(f string) bool { return selectedLine(f) != "" && selectedLine(f) != sel1 })
	// Up moves it back (SS3 encoding, as sent in application cursor mode).
	m = p.mark()
	p.send("\x1bOA")
	p.frame(m, "the selection moved back up", func(f string) bool { return selectedLine(f) == sel1 })
	_ = f

	// Typing filters, multi-byte text works, Backspace and Ctrl+U edit.
	m = p.mark()
	p.send("brav")
	p.frame(m, "only bravo matches", func(f string) bool {
		return strings.Contains(f, "brav\x1b[7m") && strings.Contains(f, "bravo_site") && !strings.Contains(f, "alpha_site")
	})
	m = p.mark()
	p.send("ü")
	p.frame(m, "the query holds ü and nothing matches", func(f string) bool {
		return strings.Contains(f, "bravü\x1b[7m") && strings.Contains(f, "(No entries found)")
	})
	m = p.mark()
	p.send("\x7f")
	p.frame(m, "Backspace removed ü", func(f string) bool {
		return strings.Contains(f, "brav\x1b[7m") && strings.Contains(f, "bravo_site")
	})
	m = p.mark()
	p.send("\x01") // Ctrl+A: cursor to the start
	p.frame(m, "the cursor is at the start", func(f string) bool { return strings.Contains(f, "\x1b[7mb\x1b[27mrav") })
	m = p.mark()
	p.send("\x1b[3~") // Delete removes the character under the cursor
	p.frame(m, "Delete removed b", func(f string) bool { return strings.Contains(f, "\x1b[7mr\x1b[27mav") })
	m = p.mark()
	p.send("\x15") // Ctrl+U clears
	p.frame(m, "the query is empty again", func(f string) bool {
		return searchFocus(f) && strings.Contains(f, "alpha_site") && strings.Contains(f, "bravo_site") &&
			strings.Contains(f, "Query:\x1b[0m \x1b[1;37m\x1b[7m \x1b[27m\x1b[0m")
	})

	// Tab focuses the list. Esc at the delete question means no, and Esc at
	// "Press Enter to continue" continues.
	m = p.mark()
	p.send("\t")
	p.frame(m, "the list has focus", listFocus)
	m = p.mark()
	p.send("d")
	p.waitFor("(y/n): ", m)
	m = p.mark()
	p.send("\x1b")
	p.waitFor("Press Enter to continue...", m)
	if strings.Contains(p.output()[m:], "Deleted.") {
		p.fail("Esc at the delete question deleted the item")
	}
	m = p.mark()
	p.send("\x1b")
	p.frame(m, "back in the list with both items", func(f string) bool {
		return listFocus(f) && strings.Contains(f, "alpha_site") && strings.Contains(f, "bravo_site")
	})

	// e opens the editor; Esc at a field prompt cancels only that field.
	m = p.mark()
	p.send("e")
	p.waitFor("Esc done", m)
	m = p.mark()
	p.send("\r")
	p.waitFor("Esc cancels", m)
	m = p.mark()
	p.send("\x1b")
	p.waitFor("Esc done", m)
	if strings.Contains(p.output()[m:], "not saved yet") {
		p.fail("Esc at a field prompt changed the field")
	}
	// Esc in the editor with no changes leaves it.
	m = p.mark()
	p.send("\x1b")
	p.waitFor("No changes.", m)
	p.waitFor("Press Enter to continue...", m)
	m = p.mark()
	p.send("\r")
	p.frame(m, "back in the list", listFocus)

	// Esc goes from the list to the search box, and Esc there exits.
	m = p.mark()
	p.send("\x1b")
	p.frame(m, "the search box has focus", searchFocus)
	p.send("\x1b")
	if code := p.waitExit(); code != 0 {
		p.fail("pm get exited %d", code)
	}
	p.assertCooked()
	p.assertNoCaretEscape()
}

func TestPTY_AddEscCancels(t *testing.T) {
	e := newPTYEnv(t)
	e.setup(t)

	// Esc at the master password prompt cancels before any unlock attempt.
	p := e.start(t, "add", "PASSWORD")
	p.waitFor("Master Password", 0)
	p.send("\x1b")
	if code := p.waitExit(); code != 1 {
		p.fail("Esc at the master password exited %d, want 1", code)
	}
	p.waitFor("Cancelled.", 0)
	p.assertCooked()

	// Esc at a later prompt cancels the add and writes nothing.
	p = e.start(t, "add", "PASSWORD")
	p.waitFor("Master Password", 0)
	p.send(ptyMasterPassword + "\r")
	p.waitFor("Account Name: ", 0)
	p.send("zulu_site\r")
	p.waitFor("Username: ", 0)
	m := p.mark()
	p.send("\x1b")
	if code := p.waitExit(); code != 1 {
		p.fail("Esc at a prompt exited %d, want 1", code)
	}
	p.waitFor("Cancelled.", m)
	if strings.Contains(p.output(), "Entry saved.") {
		p.fail("the entry was saved after Esc")
	}
	p.assertCooked()
	p.assertNoCaretEscape()

	if out := e.run(t, ptyMasterPassword+"\n", "get", "zulu_site"); !strings.Contains(out, "No matching entries found.") {
		t.Fatalf("zulu_site was written to the vault:\n%s", out)
	}
}

func TestPTY_TOTPKeys(t *testing.T) {
	e := newPTYEnv(t)
	e.setup(t)
	for _, name := range []string{"one_code", "two_code"} {
		if out := e.run(t, ptyMasterPassword+"\n"+name+"\nJBSWY3DPEHPK3PXP\n\n", "add", "totp"); !strings.Contains(out, "Entry saved.") {
			t.Fatalf("add totp %s failed:\n%s", name, out)
		}
	}

	p := e.start(t, "totp")
	p.waitFor("Master Password", 0)
	p.send(ptyMasterPassword + "\r")
	p.waitFor("> [1] one_code", 0)
	m := p.mark()
	p.send("\x1b[B")
	p.waitFor("> [2] two_code", m)
	// Shift+Up moves the selected code up and keeps it selected.
	m = p.mark()
	p.send("\x1b[1;2A")
	p.waitFor("Moved two_code up", m)
	p.waitFor("> [1] two_code", m)
	m = p.mark()
	p.send("\x1b[F") // End
	p.waitFor("> [2] one_code", m)
	p.send("\x1b")
	if code := p.waitExit(); code != 0 {
		p.fail("pm totp exited %d", code)
	}
	p.assertCooked()
	p.assertNoCaretEscape()
}
