package apm_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func runPM(t *testing.T, e *desktopEnv, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(e.pm, append([]string{"--vault", e.vault}, args...)...)
	cmd.Env = e.env
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("pm %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

func runPMOK(t *testing.T, e *desktopEnv, stdin string, args ...string) string {
	t.Helper()
	out, code := runPM(t, e, stdin, args...)
	if code != 0 {
		t.Fatalf("pm %v exited %d:\n%s", args, code, out)
	}
	return out
}

type serveProc struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan struct{}
	err  error
}

func (p *serveProc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.Write(b)
}

func (p *serveProc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

func (p *serveProc) waitFor(t *testing.T, substr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(p.output(), substr) {
			return
		}
		select {
		case <-p.done:
			if strings.Contains(p.output(), substr) {
				return
			}
			t.Fatalf("pm extension serve exited before printing %q:\n%s", substr, p.output())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %q in:\n%s", substr, p.output())
}

func (p *serveProc) stop(t *testing.T) {
	t.Helper()
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		t.Fatalf("pm extension serve did not stop on interrupt")
	}
}

func startServe(t *testing.T, e *desktopEnv, args ...string) *serveProc {
	t.Helper()
	cmd := exec.Command(e.pm, append([]string{"--vault", e.vault, "extension", "serve"}, args...)...)
	cmd.Env = e.env
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &serveProc{cmd: cmd, in: in, done: make(chan struct{})}
	cmd.Stdout = p
	cmd.Stderr = p
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = cmd.Process.Kill()
			<-p.done
		}
		if t.Failed() {
			t.Logf("pm extension serve output:\n%s", p.output())
		}
	})
	return p
}

func newVaultOnly(t *testing.T) *desktopEnv {
	t.Helper()
	e := newDesktopEnv(t)
	c := startDesktop(t, e)
	setupDesktopVault(t, c)
	c.ok("item.add", map[string]any{"type": "password", "f": map[string]any{"account": "GitHub", "username": "octo", "password": "pw-1234567", "website": "github.com"}})
	c.close()
	return e
}

func TestBridgeCLI_TokenStatusRotate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("token path differs on Windows")
	}
	e := newDesktopEnv(t)
	out := runPMOK(t, e, "", "extension", "token")
	masked := regexp.MustCompile(`Pairing token: ([0-9a-f]{6})\.\.\.([0-9a-f]{4})`).FindStringSubmatch(out)
	if masked == nil {
		t.Fatalf("masked token output:\n%s", out)
	}
	full := strings.TrimSpace(runPMOK(t, e, "", "extension", "token", "--show"))
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(full) || !strings.HasPrefix(full, masked[1]) || !strings.HasSuffix(full, masked[2]) {
		t.Fatalf("--show = %q, masked = %v", full, masked)
	}
	data, err := os.ReadFile(bridgeTokenPath(t, e.dir))
	if err != nil || strings.TrimSpace(string(data)) != full {
		t.Fatalf("token file = %q %v", data, err)
	}
	if strings.Contains(out, full) {
		t.Fatalf("the masked output printed the full token")
	}

	out, code := runPM(t, e, "", "extension", "status")
	if code == 0 || !strings.Contains(out, fmt.Sprintf("nothing is listening on 127.0.0.1:%d and no browser is linked", e.port)) {
		t.Fatalf("status with nothing running = %d:\n%s", code, out)
	}

	c := startDesktop(t, e)
	c.ok("app.hello", nil)
	waitForBridge(t, e.port)
	if got := c.ok("bridge.info", nil)["token"]; got != full {
		t.Fatalf("the desktop bridge should use the same token file: %v", got)
	}
	setupDesktopVault(t, c)
	c.ok("item.add", map[string]any{"type": "note", "f": map[string]any{"name": "Runbook", "content": "steps"}})
	out = runPMOK(t, e, "", "extension", "status")
	for _, want := range []string{"Right now:       the extension uses the APM app", fmt.Sprintf("Listening:       127.0.0.1:%d", e.port), "bridge API 2", "Vault:           unlocked, 1 items", "Token:           " + full[:6] + " (fingerprint)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, full) {
		t.Fatalf("status printed the full token")
	}

	out = runPMOK(t, e, "", "extension", "rotate")
	if !strings.Contains(out, "New pairing token") {
		t.Fatalf("rotate output:\n%s", out)
	}
	rotated := strings.TrimSpace(runPMOK(t, e, "", "extension", "token", "--show"))
	if rotated == full || len(rotated) != 64 {
		t.Fatalf("token did not rotate: %q", rotated)
	}
	newBridgeTester(t, e.port, full).fails("GET", "/api/status", nil, 401, "unauthorized")
	newBridgeTester(t, e.port, rotated).ok("GET", "/api/status", nil)
	if got := c.ok("bridge.info", nil)["token"]; got != rotated {
		t.Fatalf("the running bridge did not pick up the rotated token: %v", got)
	}
	snap := c.ok("vault.snapshot", nil)
	found := false
	for _, a := range itemsOf(snap, "audit") {
		if a["action"] == "BRIDGE_TOKEN_ROTATED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rotate should log BRIDGE_TOKEN_ROTATED")
	}

	c.ok("vault.lock", nil)
	out = runPMOK(t, e, "", "extension", "status")
	if !strings.Contains(out, "Vault:           locked") {
		t.Fatalf("status after lock:\n%s", out)
	}
}

func TestBridgeCLI_ServeLockedAndPairing(t *testing.T) {
	e := newVaultOnly(t)
	p := startServe(t, e, "--locked", "--prompt-stdin", "--idle", "0")
	p.waitFor(t, fmt.Sprintf("Browser extension bridge on 127.0.0.1:%d · %s · locked", e.port, e.vault))
	waitForBridge(t, e.port)

	anon := newBridgeTester(t, e.port, "")
	anon.origin = "chrome-extension://abcdefghijklmnop"
	info := anon.ok("GET", "/api/info", nil)
	if info["name"] != "APM" || info["api"].(float64) != 2 || info["unlocked"] != false {
		t.Fatalf("/api/info = %v", info)
	}
	token := strings.TrimSpace(runPMOK(t, e, "", "extension", "token", "--show"))
	if out := runPMOK(t, e, "", "extension", "status"); !strings.Contains(out, "Right now:       the extension uses 'pm extension serve'") || !strings.Contains(out, "Vault:           locked") {
		t.Fatalf("status while serving:\n%s", out)
	}
	b := newBridgeTester(t, e.port, token)
	b.origin = anon.origin
	b.fails("GET", "/api/items", nil, 423, "locked")
	b.fails("POST", "/api/unlock", map[string]any{"password": "wrong"}, 401, "wrong_password")
	res := b.ok("POST", "/api/unlock", map[string]any{"password": desktopPassword})
	if st := res["status"].(map[string]any); st["unlocked"] != true || st["items"].(float64) != 1 {
		t.Fatalf("unlock through serve = %v", res)
	}
	p.waitFor(t, "Vault unlocked from the browser.")
	status := b.ok("GET", "/api/status", nil)
	want := []string{"activeSpace", "cooldown", "exists", "items", "left", "name", "ok", "readonly", "settings", "spaces", "touchId", "unlocked", "version"}
	if got := keysOf(status); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("serve status keys = %v", got)
	}
	items := listOf(b.ok("GET", "/api/items", nil)["items"])
	if len(items) != 1 || items[0]["title"] != "GitHub" {
		t.Fatalf("serve items = %v", items)
	}

	start := anon.ok("POST", "/api/pair/start", map[string]any{"client": "Chrome 131 on macOS"})
	code := start["code"].(string)
	p.waitFor(t, fmt.Sprintf("Connect Chrome 131 on macOS? Code %s-%s [y/N]", code[:3], code[3:]))
	if _, err := io.WriteString(p.in, "y\n"); err != nil {
		t.Fatal(err)
	}
	p.waitFor(t, "Connected Chrome 131 on macOS.")
	got := anon.ok("GET", "/api/pair/poll?id="+start["id"].(string), nil)
	if got["status"] != "approved" || got["token"] != token {
		t.Fatalf("poll after terminal approval = %v", got)
	}
	anon.fails("GET", "/api/pair/poll?id="+start["id"].(string), nil, 404, "not_found")

	start = anon.ok("POST", "/api/pair/start", map[string]any{"client": "Firefox"})
	p.waitFor(t, "Connect Firefox?")
	if _, err := io.WriteString(p.in, "n\n"); err != nil {
		t.Fatal(err)
	}
	p.waitFor(t, "Did not connect Firefox.")
	if got := anon.ok("GET", "/api/pair/poll?id="+start["id"].(string), nil); got["status"] != "denied" || got["token"] != nil {
		t.Fatalf("poll after terminal deny = %v", got)
	}

	b.ok("POST", "/api/lock", nil)
	p.waitFor(t, "Vault locked: Locked from the browser.")
	p.stop(t)
	if p.err != nil {
		t.Fatalf("serve should exit cleanly on interrupt: %v\n%s", p.err, p.output())
	}
	if !strings.Contains(p.output(), "Bridge stopped.") {
		t.Fatalf("missing stop message:\n%s", p.output())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port
	out, exit := runPM(t, e, "", "extension", "serve", "--locked", "--port", strconv.Itoa(busy))
	if exit == 0 || !strings.Contains(out, fmt.Sprintf("Port %d is in use. The APM app may already be serving the extension.", busy)) {
		t.Fatalf("serve on a busy port = %d:\n%s", exit, out)
	}
}

func TestBridgeCLI_ServeNonTerminalDenies(t *testing.T) {
	e := newVaultOnly(t)
	p := startServe(t, e, "--locked")
	p.waitFor(t, "· locked")
	waitForBridge(t, e.port)
	anon := newBridgeTester(t, e.port, "")
	start := anon.ok("POST", "/api/pair/start", map[string]any{"client": "Edge"})
	p.waitFor(t, "Denied because this terminal cannot answer")
	if got := anon.ok("GET", "/api/pair/poll?id="+start["id"].(string), nil); got["status"] != "denied" {
		t.Fatalf("non-terminal serve should deny: %v", got)
	}
	p.stop(t)
}

func TestBridgeCLI_ServeSessionAndIdle(t *testing.T) {
	e := newVaultOnly(t)
	p := startServe(t, e, "--idle", "1s")
	p.waitFor(t, "· unlocked")
	waitForBridge(t, e.port)
	token := strings.TrimSpace(runPMOK(t, e, "", "extension", "token", "--show"))
	b := newBridgeTester(t, e.port, token)
	if items := listOf(b.ok("GET", "/api/items", nil)["items"]); len(items) != 1 {
		t.Fatalf("serve should reuse the CLI session: %v", items)
	}
	time.Sleep(2500 * time.Millisecond)
	p.waitFor(t, "Vault locked: No browser activity for 1s.")
	if st := b.ok("GET", "/api/status", nil); st["unlocked"] != false {
		t.Fatalf("serve should lock after the idle timeout: %v", st)
	}
	p.stop(t)
}

func TestPasskeysAndTOTPLinkCLI(t *testing.T) {
	e, c, b := startBridgeEnv(t)
	setupDesktopVault(t, c)
	zy := c.ok("item.add", map[string]any{"type": "password", "f": map[string]any{"account": "Zyxwv", "username": "octo", "password": "pw-1234567", "website": "github.com", "urls": []string{"gist.github.com"}}})["item"].(map[string]any)
	work := c.ok("item.add", map[string]any{"type": "password", "f": map[string]any{"account": "GitHub Work", "username": "octo-work", "password": "pw-7654321"}})["item"].(map[string]any)
	ex := c.ok("item.add", map[string]any{"type": "password", "f": map[string]any{"account": "Example", "username": "you", "password": "pw-0000000"}})["item"].(map[string]any)
	c.ok("item.add", map[string]any{"type": "totp", "f": map[string]any{"account": "Octo 2FA", "secret": "JBSWY3DPEHPK3PXP"}})

	create := func(origin, rp, user, target string) map[string]any {
		cdh := sha256.Sum256([]byte(origin + user))
		return b.ok("POST", "/api/passkeys/create", map[string]any{"origin": origin, "rpId": rp, "user": map[string]any{"id": b64u([]byte(user)), "name": user}, "clientDataHash": b64u(cdh[:]), "target": map[string]any{"id": target}})
	}
	pkZy := create("https://github.com", "github.com", "octo", zy["id"].(string))
	create("https://github.com", "github.com", "octo-work", work["id"].(string))
	create("https://example.com", "example.com", "you", ex["id"].(string))

	privateDs := func() []string {
		v := decodeVaultFile(t, e.vault, desktopPassword)
		out := []string{}
		for _, en := range v.Entries {
			for _, pk := range en.Passkeys {
				var jwk struct {
					D string `json:"d"`
				}
				_ = json.Unmarshal(pk.PrivateKey, &jwk)
				out = append(out, jwk.D)
			}
		}
		return out
	}
	ds := privateDs()
	if len(ds) != 3 {
		t.Fatalf("expected 3 stored passkeys, got %d", len(ds))
	}

	// Passkeys are managed in the app and in pm get's editor; there is no
	// separate pm passkeys command any more.
	out, code := runPM(t, e, "", "passkeys", "list")
	if !strings.Contains(out, `unknown command "passkeys"`) {
		t.Fatalf("pm passkeys should be gone:\n%s", out)
	}

	out = runPMOK(t, e, "", "totp", "link", "Octo 2FA", "https://www.github.com/login")
	if !strings.Contains(out, "Linked Octo 2FA to github.com.") {
		t.Fatalf("totp link:\n%s", out)
	}
	totpID := ""
	deadline := time.Now().Add(10 * time.Second)
	for totpID == "" {
		for _, it := range listOf(b.ok("GET", "/api/items", nil)["items"]) {
			if it["title"] == "Zyxwv" && it["totpId"] != "" {
				totpID = it["totpId"].(string)
			}
		}
		if totpID == "" {
			if time.Now().After(deadline) {
				t.Fatalf("the login did not link to the authenticator after pm totp link")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// Linking the code to the login's site folds it into that login on the
	// next unlock, so the code is then served under the login's own name.
	if one := b.ok("GET", "/api/totp/"+zy["id"].(string), nil)["code"].(map[string]any); (one["title"] != "Octo 2FA" && one["title"] != "Zyxwv") || one["domain"] != "github.com" {
		t.Fatalf("linked code = %v", one)
	}
	out = runPMOK(t, e, "", "totp")
	if !strings.Contains(out, "Zyxwv") || !strings.Contains(out, "(github.com)") {
		t.Fatalf("pm totp should show the linked site:\n%s", out)
	}
	out = runPMOK(t, e, "", "get", "zyxwv")
	if !strings.Contains(out, "1 passkey") || !strings.Contains(out, "Passkeys") || !strings.Contains(out, "One-time code") || strings.Contains(out, "pw-1234567") {
		t.Fatalf("pm get login details:\n%s", out)
	}
	for _, d := range ds {
		if strings.Contains(out, d) {
			t.Fatalf("pm get leaked a private key")
		}
	}

	cdh := sha256.Sum256([]byte("after cli writes"))
	a := b.ok("POST", "/api/passkeys/assert", map[string]any{"origin": "https://github.com", "rpId": "github.com", "credentialId": pkZy["credentialId"], "clientDataHash": b64u(cdh[:])})
	pubAny, err := x509.ParsePKIXPublicKey(unb64u(t, pkZy["publicKey"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	verifyAssertion(t, pubAny.(*ecdsa.PublicKey), a, cdh[:], "github.com", 0, false)

	out, code = runPM(t, e, "", "totp", "unlink", "Octo 2FA")
	if code == 0 || !strings.Contains(out, "No TOTP entry matches") {
		t.Fatalf("the code should live inside the login now, unlink = %d:\n%s", code, out)
	}
	out, code = runPM(t, e, "", "totp", "link", "Nope", "github.com")
	if code == 0 || !strings.Contains(out, "No TOTP entry matches") {
		t.Fatalf("link of a missing entry = %d:\n%s", code, out)
	}

	final := decodeVaultFile(t, e.vault, desktopPassword)
	for _, en := range final.Entries {
		if en.Account == "Zyxwv" && (len(en.Passkeys) != 1 || en.Passkeys[0].SignCount != 0 || en.Website != "github.com" || len(en.URLs) != 1 || en.TOTP != "JBSWY3DPEHPK3PXP") {
			t.Fatalf("Zyxwv after CLI writes = %+v", en)
		}
	}
}
