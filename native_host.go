package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
)

// The browser extension talks to the desktop app over 127.0.0.1. When the app
// is not running, the browser starts pm itself through native messaging and the
// extension sends the same requests over stdio. pm extension link registers pm
// with the browser and approves the extension once.

const nativeHostName = "dev.apm.bridge"

// apmExtensionID is pinned by the manifest key in extension/scripts.
const apmExtensionID = "ioooalainhfihaebgpbmngoaojmfdlac"

// nativeChunk keeps each message under the 1 MiB the browser accepts from a
// native host.
const nativeChunk = 512 * 1024

const nativeInLimit = 4 << 20

type nativeRequest struct {
	ID     json.Number     `json:"id"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
	Token  string          `json:"token"`
	Client string          `json:"client"`
}

// nativeHostConfig is written by pm extension link. The browser starts pm with
// its own environment, so the host cannot rely on APM_VAULT_PATH.
type nativeHostConfig struct {
	Vault    string   `json:"vault"`
	Path     string   `json:"path"`
	Linked   int64    `json:"linked"`
	Browsers []string `json:"browsers"`
	IDs      []string `json:"ids"`
}

func apmConfigDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "apm")
}

func nativeHostConfigFile() string {
	if d := apmConfigDir(); d != "" {
		return filepath.Join(d, "native_host.json")
	}
	return ""
}

func readNativeHostConfig() (nativeHostConfig, bool) {
	var c nativeHostConfig
	file := nativeHostConfigFile()
	if file == "" {
		return c, false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return c, false
	}
	if json.Unmarshal(data, &c) != nil {
		return c, false
	}
	return c, true
}

func writeJSONFile(file string, v any) error {
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// nativeHostOrigin reports whether the browser started pm as a native host.
// Chromium passes the caller's origin as the first argument, and on Windows a
// --parent-window flag after it.
func nativeHostOrigin(args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	if strings.HasPrefix(args[0], "chrome-extension://") && len(args[0]) > len("chrome-extension://") {
		return args[0], true
	}
	return "", false
}

type nativeHost struct {
	s      *desktopServer
	origin string
	out    io.Writer
	wmu    sync.Mutex
	locker *autoLocker
}

func runNativeHost(origin string) int {
	proto := os.Stdout
	os.Stdout = os.Stderr
	color.Output = os.Stderr
	color.Error = os.Stderr
	if os.Getenv("APM_VAULT_PATH") == "" {
		if c, ok := readNativeHostConfig(); ok && c.Vault != "" && filepath.IsAbs(c.Vault) {
			vaultPath = filepath.Clean(c.Vault)
		}
	}
	if err := serveNative(origin, os.Stdin, proto); err != nil {
		fmt.Fprintf(os.Stderr, "pm native host stopped: %v\n", err)
		return 1
	}
	return 0
}

func serveNative(origin string, in io.Reader, out io.Writer) error {
	s := newDesktopServer(nil)
	s.bridge.mode = "native"
	s.bridge.mu.Lock()
	s.bridge.loadToken()
	s.bridge.mu.Unlock()
	h := &nativeHost{s: s, origin: strings.TrimSuffix(origin, "/"), out: out}
	h.locker = newAutoLocker(s)
	s.sink = h.event
	s.startWatcher()
	stop := make(chan struct{})
	go h.locker.run(stop)
	defer func() {
		close(stop)
		s.shutdown()
	}()

	r := bufio.NewReader(in)
	var wg sync.WaitGroup
	for {
		msg, err := readNativeMessage(r)
		if err != nil {
			wg.Wait()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.handle(msg)
		}()
	}
}

func readNativeMessage(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	if n > nativeInLimit {
		return nil, fmt.Errorf("message of %d bytes is over the %d byte limit", n, nativeInLimit)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (h *nativeHost) writeMessage(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.wmu.Lock()
	defer h.wmu.Unlock()
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(data)))
	_, _ = h.out.Write(size[:])
	_, _ = h.out.Write(data)
}

// reply sends one answer. Answers over nativeChunk go out as numbered parts
// of the serialized answer, cut on UTF-8 boundaries.
func (h *nativeHost) reply(id json.Number, status int, body json.RawMessage) {
	whole, err := json.Marshal(map[string]any{"id": id, "status": status, "body": body})
	if err != nil {
		return
	}
	if len(whole) <= nativeChunk {
		h.writeMessage(json.RawMessage(whole))
		return
	}
	var parts []string
	for len(whole) > 0 {
		cut := nativeChunk
		if cut >= len(whole) {
			cut = len(whole)
		} else {
			for cut > 0 && !utf8.RuneStart(whole[cut]) {
				cut--
			}
		}
		parts = append(parts, string(whole[:cut]))
		whole = whole[cut:]
	}
	for i, p := range parts {
		h.writeMessage(map[string]any{"id": id, "part": i, "parts": len(parts), "chunk": p})
	}
}

func (h *nativeHost) fail(id json.Number, status int, code, message string) {
	body, _ := json.Marshal(map[string]any{"ok": false, "code": code, "error": message})
	h.reply(id, status, body)
}

func (h *nativeHost) handle(raw []byte) {
	var req nativeRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil || req.ID == "" {
		h.writeMessage(map[string]any{"event": "host.error", "data": map[string]any{"message": "Malformed request."}})
		return
	}
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		h.fail(req.ID, 400, "invalid", "Only GET and POST are supported.")
		return
	}
	if !strings.HasPrefix(req.Path, "/api/") {
		h.fail(req.ID, 404, "not_found", "There is no "+req.Method+" "+req.Path+" endpoint.")
		return
	}
	h.adoptSession(req.Path)
	var body io.Reader
	if req.Method == http.MethodPost {
		b := req.Body
		if len(b) == 0 || string(b) == "null" {
			b = json.RawMessage("{}")
		}
		body = bytes.NewReader(b)
	}
	hr, err := http.NewRequest(req.Method, "http://127.0.0.1:"+strconv.Itoa(h.s.bridge.port)+req.Path, body)
	if err != nil {
		h.fail(req.ID, 400, "invalid", "That request could not be read.")
		return
	}
	hr.Header.Set("Origin", h.origin)
	if body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	if req.Token != "" {
		hr.Header.Set("x-apm-token", req.Token)
	}
	if req.Client != "" {
		hr.Header.Set("x-apm-client", req.Client)
	}
	w := &nativeWriter{h: http.Header{}}
	h.s.bridge.handle(w, hr)
	if w.code == 0 {
		w.code = 200
	}
	if w.code == 200 && req.Token != "" {
		h.noteConnected(req.Client)
	}
	out := bytes.TrimSpace(w.buf.Bytes())
	if len(out) == 0 || !json.Valid(out) {
		out = []byte(`{}`)
	}
	h.reply(req.ID, w.code, out)
}

// adoptSession unlocks with the terminal's pm session when there is one, the
// same way the desktop app does at launch. Locking from the browser ends that
// session, so this never undoes a lock.
func (h *nativeHost) adoptSession(path string) {
	if path == "/api/info" || strings.HasPrefix(path, "/api/pair/") {
		return
	}
	s := h.s
	s.mu.Lock()
	if s.unlocked() {
		s.mu.Unlock()
		return
	}
	if sess, err := src.PeekSession(); err != nil || sess == nil {
		s.mu.Unlock()
		return
	}
	res, err := hVaultUnlockSession(s, nil)
	if err == nil {
		s.emit("vault.unlocked", map[string]any{"snapshot": snapshotFromResult(res), "via": "session"})
	}
	s.mu.Unlock()
}

func (h *nativeHost) event(name string, data any) {
	d, _ := data.(map[string]any)
	switch name {
	case "vault.unlocked":
		h.locker.markUnlocked()
		h.writeMessage(map[string]any{"event": name})
	case "vault.locked":
		h.writeMessage(map[string]any{"event": name, "data": map[string]any{"reason": toStr(d["reason"]), "why": toStr(d["why"])}})
	case "vault.changed":
		h.writeMessage(map[string]any{"event": name})
	case "bridge.activity":
		h.locker.touch()
	}
}

// noteConnected leaves a mark that pm extension link waits for, so it can
// say the browser is connected when the extension was already paired.
func (h *nativeHost) noteConnected(client string) {
	h.s.bridge.mu.Lock()
	first := !h.s.bridge.nativeSeen
	h.s.bridge.nativeSeen = true
	h.s.bridge.mu.Unlock()
	if !first {
		return
	}
	file := extensionSeenFile()
	if file == "" {
		return
	}
	_ = writeJSONFile(file, map[string]any{"ts": ms(time.Now()), "client": bridgeClientName(client), "origin": h.origin})
}

type nativeWriter struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (w *nativeWriter) Header() http.Header { return w.h }

func (w *nativeWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}

func (w *nativeWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	return w.buf.Write(p)
}

// Pairing without the app. The host cannot ask anyone, so it leaves the
// request in a file that pm extension link, running in a terminal, answers.

type linkRequest struct {
	ID      string `json:"id"`
	Code    string `json:"code"`
	Client  string `json:"client"`
	Origin  string `json:"origin"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	Status  string `json:"status"`
}

func extensionLinkFile() string {
	if d := apmConfigDir(); d != "" {
		return filepath.Join(d, "extension_link.json")
	}
	return ""
}

func extensionSeenFile() string {
	if d := apmConfigDir(); d != "" {
		return filepath.Join(d, "extension_seen.json")
	}
	return ""
}

func readLinkRequest() (*linkRequest, error) {
	file := extensionLinkFile()
	if file == "" {
		return nil, errors.New("no configuration directory")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var r linkRequest
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func writeLinkRequest(r *linkRequest) error {
	file := extensionLinkFile()
	if file == "" {
		return errors.New("no configuration directory")
	}
	return writeJSONFile(file, r)
}

func removeLinkRequest() {
	if file := extensionLinkFile(); file != "" {
		_ = os.Remove(file)
	}
}

func (b *desktopBridge) startLinkPair(client, origin string) (map[string]any, error) {
	now := time.Now()
	b.mu.Lock()
	kept := b.starts[:0]
	for _, t := range b.starts {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	b.starts = kept
	if len(b.starts) >= 5 {
		wait := int((time.Minute - now.Sub(b.starts[0]) + time.Second - 1) / time.Second)
		if wait < 1 {
			wait = 1
		}
		b.mu.Unlock()
		return nil, rpcErrData("cooldown", fmt.Sprintf("Too many pairing requests. Try again in %d seconds.", wait), map[string]any{"wait": wait})
	}
	b.starts = append(b.starts, now)
	b.mu.Unlock()
	if cur, err := readLinkRequest(); err == nil && cur.Status == "pending" && now.UnixMilli() < cur.Expires && cur.Origin == origin {
		return map[string]any{"id": cur.ID, "code": cur.Code, "expires": cur.Expires, "via": "link"}, nil
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	code, err := randomPairCode()
	if err != nil {
		return nil, err
	}
	r := &linkRequest{ID: hex.EncodeToString(idBytes), Code: code, Client: client, Origin: origin, Created: ms(now), Expires: ms(now.Add(bridgePairTTL)), Status: "pending"}
	if err := writeLinkRequest(r); err != nil {
		return nil, rpcErr("internal", "Could not record the pairing request: "+err.Error())
	}
	return map[string]any{"id": r.ID, "code": r.Code, "expires": r.Expires, "via": "link"}, nil
}

func (b *desktopBridge) pollLinkPair(id string) (map[string]any, error) {
	r, err := readLinkRequest()
	if err != nil || id == "" || r.ID != id {
		return nil, rpcErr("not_found", "That pairing request does not exist. Start pairing again.")
	}
	now := time.Now().UnixMilli()
	switch r.Status {
	case "pending":
		if now > r.Expires {
			removeLinkRequest()
			return map[string]any{"status": "expired"}, nil
		}
		return map[string]any{"status": "pending"}, nil
	case "approved":
		removeLinkRequest()
		if now > r.Expires+bridgePairGrace.Milliseconds() {
			return map[string]any{"status": "expired"}, nil
		}
		b.mu.Lock()
		b.refreshTokenLocked()
		token := b.token
		b.mu.Unlock()
		return map[string]any{"status": "approved", "token": token}, nil
	default:
		removeLinkRequest()
		return map[string]any{"status": r.Status}, nil
	}
}
