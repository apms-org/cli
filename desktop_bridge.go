package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	src "github.com/aaravmaloo/apm/src"
)

const defaultBridgePort = 41417

const bridgeAPIVersion = 2

const bridgeBodyLimit = 1 << 20

const bridgePairTTL = 120 * time.Second

const bridgePairGrace = 120 * time.Second

const bridgeActivityEvery = 15 * time.Second

const bridgePairAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

var bridgeHTTPStatus = map[string]int{
	"invalid":             400,
	"unauthorized":        401,
	"forbidden_origin":    403,
	"forbidden_host":      403,
	"rp_mismatch":         403,
	"not_found":           404,
	"not_login":           400,
	"exists":              409,
	"locked":              423,
	"readonly":            423,
	"wrong_password":      401,
	"cooldown":            429,
	"breach_lock":         423,
	"no_vault":            404,
	"touchid_unavailable": 400,
	"touchid_failed":      400,
	"pair_expired":        410,
	"pair_denied":         403,
	"internal":            500,
}

type bridgePair struct {
	id      string
	code    string
	client  string
	expires time.Time
	status  string
}

type bridgeSeen struct {
	ts     time.Time
	client string
	origin string
}

type desktopBridge struct {
	s            *desktopServer
	mu           sync.Mutex
	token        string
	tokenMod     time.Time
	port         int
	server       *http.Server
	running      bool
	lastErr      string
	pairs        map[string]*bridgePair
	pending      string
	starts       []time.Time
	seen         *bridgeSeen
	lastActivity time.Time
	lastActive   time.Time
	// mode is who serves the bridge: "app" (pm desktop), "serve" (pm bridge
	// serve) or "native" (pm started by the browser through native messaging).
	// In native mode pairing goes through pm extension link instead of a prompt.
	mode string
	// nativeSeen is set once the native host has answered a paired request.
	nativeSeen bool
}

type bridgeCtx struct {
	r      *http.Request
	body   json.RawMessage
	params map[string]string
	client string
	origin string
}

type bridgeHandler func(b *desktopBridge, c *bridgeCtx) (map[string]any, error)

type bridgeRoute struct {
	method   string
	pattern  string
	fn       bridgeHandler
	public   bool
	lock     bool
	unlocked bool
	// passive routes are the ones the extension calls on its own (status
	// polls, badge counts, logos). They do not count as activity for auto-lock.
	passive bool
}

var bridgeRoutes []bridgeRoute

func init() {
	bridgeRoutes = []bridgeRoute{
		{method: "GET", pattern: "/api/info", fn: bridgeInfoRoute, public: true, lock: true, passive: true},
		{method: "POST", pattern: "/api/pair/start", fn: bridgePairStart, public: true, passive: true},
		{method: "GET", pattern: "/api/pair/poll", fn: bridgePairPoll, public: true, passive: true},
		{method: "GET", pattern: "/api/status", fn: bridgeStatusRoute, lock: true, passive: true},
		{method: "POST", pattern: "/api/unlock", fn: bridgeUnlock, lock: true},
		{method: "POST", pattern: "/api/unlock/touchid", fn: bridgeUnlockTouchID},
		{method: "POST", pattern: "/api/lock", fn: bridgeLock, lock: true},
		{method: "GET", pattern: "/api/items", fn: bridgeItemsList, lock: true, unlocked: true, passive: true},
		{method: "POST", pattern: "/api/items", fn: bridgeItemAdd, lock: true, unlocked: true},
		{method: "GET", pattern: "/api/items/:id", fn: bridgeItemGet, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/items/:id/reveal", fn: bridgeItemReveal, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/items/:id/update", fn: bridgeItemUpdate, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/items/:id/trash", fn: bridgeItemTrash, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/items/:id/favorite", fn: bridgeItemFavorite, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/fill", fn: bridgeFill, lock: true, unlocked: true},
		{method: "GET", pattern: "/api/totp", fn: bridgeTOTPList, lock: true, unlocked: true},
		{method: "GET", pattern: "/api/totp/:id", fn: bridgeTOTPOne, lock: true, unlocked: true},
		{method: "GET", pattern: "/api/passkeys", fn: bridgePasskeyList, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/passkeys/rename", fn: bridgePasskeyRename, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/passkeys/remove", fn: bridgePasskeyRemove, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/passkeys/create", fn: bridgePasskeyCreate, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/passkeys/assert", fn: bridgePasskeyAssert, lock: true, unlocked: true},
		{method: "POST", pattern: "/api/icons", fn: bridgeIcons, lock: true, unlocked: true, passive: true},
	}
}

func newDesktopBridge(s *desktopServer) *desktopBridge {
	return &desktopBridge{s: s, port: bridgePortFromEnv(), pairs: map[string]*bridgePair{}, mode: "app"}
}

func bridgePortFromEnv() int {
	if v := strings.TrimSpace(os.Getenv("APM_BRIDGE_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return defaultBridgePort
}

func bridgeTokenFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	apmDir := filepath.Join(dir, "apm")
	_ = os.MkdirAll(apmDir, 0700)
	return filepath.Join(apmDir, "bridge_token")
}

func newBridgeToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func readBridgeToken(file string) (string, time.Time, bool) {
	st, err := os.Stat(file)
	if err != nil {
		return "", time.Time{}, false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", time.Time{}, false
	}
	t := strings.TrimSpace(string(data))
	return t, st.ModTime(), t != ""
}

func ensureBridgeToken() (string, error) {
	file := bridgeTokenFile()
	if file == "" {
		return "", errors.New("no configuration directory for the bridge token")
	}
	if t, _, ok := readBridgeToken(file); ok {
		return t, nil
	}
	t := newBridgeToken()
	if err := os.WriteFile(file, []byte(t), 0600); err != nil {
		return "", err
	}
	return t, nil
}

func writeBridgeToken(t string) error {
	file := bridgeTokenFile()
	if file == "" {
		return errors.New("no configuration directory for the bridge token")
	}
	return os.WriteFile(file, []byte(t), 0600)
}

func (b *desktopBridge) loadToken() {
	file := bridgeTokenFile()
	if file != "" {
		if t, mod, ok := readBridgeToken(file); ok {
			b.token = t
			b.tokenMod = mod
			return
		}
	}
	b.token = newBridgeToken()
	if file != "" {
		_ = os.WriteFile(file, []byte(b.token), 0600)
		if st, err := os.Stat(file); err == nil {
			b.tokenMod = st.ModTime()
		}
	}
}

func (b *desktopBridge) refreshTokenLocked() {
	file := bridgeTokenFile()
	if file == "" {
		return
	}
	st, err := os.Stat(file)
	if err != nil || st.ModTime().Equal(b.tokenMod) {
		return
	}
	if t, mod, ok := readBridgeToken(file); ok {
		b.token = t
		b.tokenMod = mod
	}
}

func (b *desktopBridge) start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.loadToken()
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(b.port))
	if err != nil {
		b.running = false
		b.lastErr = err.Error()
		return err
	}
	b.server = &http.Server{Handler: http.HandlerFunc(b.handle), ReadHeaderTimeout: 10 * time.Second}
	b.running = true
	go func() {
		_ = b.server.Serve(ln)
		b.mu.Lock()
		b.running = false
		b.mu.Unlock()
	}()
	return nil
}

func (b *desktopBridge) stop() {
	b.mu.Lock()
	srv := b.server
	b.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func (b *desktopBridge) info() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshTokenLocked()
	res := map[string]any{"token": b.token, "port": b.port, "running": b.running, "lastSeen": nil, "pair": nil}
	if b.lastErr != "" && !b.running {
		res["error"] = b.lastErr
	}
	if b.seen != nil {
		res["lastSeen"] = map[string]any{"ts": ms(b.seen.ts), "client": b.seen.client, "origin": b.seen.origin}
	}
	if p := b.pendingPairLocked(); p != nil {
		res["pair"] = p.view()
	}
	return res
}

func (b *desktopBridge) lastSeenAt() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil {
		return time.Time{}
	}
	return b.seen.ts
}

// lastActiveAt is the last request someone made on purpose: a fill, a reveal,
// an unlock. Status polls and badge counts leave it alone.
func (b *desktopBridge) lastActiveAt() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastActive
}

func (b *desktopBridge) rotate() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.token = newBridgeToken()
	if file := bridgeTokenFile(); file != "" {
		if err := os.WriteFile(file, []byte(b.token), 0600); err != nil {
			return err
		}
		if st, err := os.Stat(file); err == nil {
			b.tokenMod = st.ModTime()
		}
	}
	return nil
}

func (b *desktopBridge) currentToken() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshTokenLocked()
	return b.token
}

func bridgeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func bridgeFail(w http.ResponseWriter, err error) {
	var re *rpcError
	if !errors.As(err, &re) {
		re = mapGoError(err)
	}
	code := re.Code
	status, ok := bridgeHTTPStatus[code]
	if !ok {
		code = "internal"
		status = 500
	}
	out := map[string]any{"ok": false, "code": code, "error": re.Message}
	if len(re.Data) > 0 {
		out["data"] = re.Data
	}
	bridgeJSON(w, status, out)
}

func bridgeOriginAllowed(origin string) bool {
	for _, p := range []string{"chrome-extension://", "moz-extension://", "safari-web-extension://"} {
		if strings.HasPrefix(origin, p) && len(origin) > len(p) {
			return true
		}
	}
	return false
}

func (b *desktopBridge) hostAllowed(host string) bool {
	p := strconv.Itoa(b.port)
	return strings.EqualFold(host, "127.0.0.1:"+p) || strings.EqualFold(host, "localhost:"+p)
}

func bridgeClientName(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if r := []rune(v); len(r) > 80 {
		v = strings.TrimSpace(string(r[:80]))
	}
	return v
}

func matchBridgePattern(pattern, path string) (map[string]string, bool) {
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	ap := strings.Split(strings.Trim(path, "/"), "/")
	if len(pp) != len(ap) {
		return nil, false
	}
	params := map[string]string{}
	for i := range pp {
		if strings.HasPrefix(pp[i], ":") {
			if ap[i] == "" {
				return nil, false
			}
			params[pp[i][1:]] = ap[i]
			continue
		}
		if pp[i] != ap[i] {
			return nil, false
		}
	}
	return params, true
}

func findBridgeRoute(method, path string) (*bridgeRoute, map[string]string) {
	for i := range bridgeRoutes {
		rt := &bridgeRoutes[i]
		if rt.method != method {
			continue
		}
		if params, ok := matchBridgePattern(rt.pattern, path); ok {
			return rt, params
		}
	}
	return nil, nil
}

func readBridgeBody(r *http.Request) (json.RawMessage, error) {
	if r.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, bridgeBodyLimit+1))
	if err != nil {
		return nil, rpcErr("invalid", "The request body could not be read.")
	}
	if len(raw) > bridgeBodyLimit {
		return nil, rpcErr("invalid", "The request body is larger than 1 MiB.")
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if ct := strings.ToLower(r.Header.Get("Content-Type")); !strings.Contains(ct, "application/json") {
		return nil, rpcErr("invalid", "Send the body as JSON with content-type application/json.")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return nil, rpcErr("invalid", "The request body is not a JSON object.")
	}
	return json.RawMessage(trimmed), nil
}

func (c *bridgeCtx) decode(v any) error {
	return decodeParams(c.body, v)
}

func (b *desktopBridge) handle(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			bridgeFail(w, rpcErr("internal", fmt.Sprintf("Internal error: %v", rec)))
		}
	}()
	w.Header().Set("Vary", "Origin")
	if !b.hostAllowed(r.Host) {
		bridgeFail(w, rpcErr("forbidden_host", "This bridge only answers requests sent to 127.0.0.1 or localhost."))
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !bridgeOriginAllowed(origin) {
			bridgeFail(w, rpcErr("forbidden_origin", "Only the APM browser extension can call this bridge."))
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "content-type, x-apm-token, x-apm-client")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	route, params := findBridgeRoute(r.Method, r.URL.Path)
	if route == nil || !route.public {
		if !b.authorized(r.Header.Get("x-apm-token")) {
			bridgeFail(w, rpcErr("unauthorized", "This browser is not paired with APM, or its pairing token is out of date. Pair it again."))
			return
		}
		b.touch(bridgeClientName(r.Header.Get("x-apm-client")), origin, route != nil && !route.passive)
	}
	if route == nil {
		bridgeFail(w, rpcErr("not_found", "There is no "+r.Method+" "+r.URL.Path+" endpoint."))
		return
	}
	c := &bridgeCtx{r: r, params: params, client: bridgeClientName(r.Header.Get("x-apm-client")), origin: origin}
	if r.Method == http.MethodPost {
		body, err := readBridgeBody(r)
		if err != nil {
			bridgeFail(w, err)
			return
		}
		c.body = body
	}
	res, err := b.run(route, c)
	if err != nil {
		bridgeFail(w, err)
		return
	}
	if res == nil {
		res = map[string]any{}
	}
	res["ok"] = true
	bridgeJSON(w, 200, res)
}

func (b *desktopBridge) run(route *bridgeRoute, c *bridgeCtx) (map[string]any, error) {
	if !route.lock {
		return route.fn(b, c)
	}
	s := b.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if route.unlocked {
		if err := s.requireUnlocked(); err != nil {
			return nil, err
		}
	}
	return route.fn(b, c)
}

func (b *desktopBridge) authorized(token string) bool {
	cur := b.currentToken()
	if token == "" || cur == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(cur)) == 1
}

func (b *desktopBridge) touch(client, origin string, active bool) {
	now := time.Now()
	b.mu.Lock()
	b.seen = &bridgeSeen{ts: now, client: client, origin: origin}
	if !active {
		b.mu.Unlock()
		return
	}
	b.lastActive = now
	fire := b.lastActivity.IsZero() || now.Sub(b.lastActivity) >= bridgeActivityEvery
	if fire {
		b.lastActivity = now
	}
	b.mu.Unlock()
	if fire {
		b.s.emit("bridge.activity", map[string]any{"ts": ms(now), "client": client})
	}
}

func (p *bridgePair) view() map[string]any {
	return map[string]any{"id": p.id, "code": p.code, "client": p.client, "expires": ms(p.expires)}
}

func (b *desktopBridge) pendingPairLocked() *bridgePair {
	if b.pending == "" {
		return nil
	}
	p, ok := b.pairs[b.pending]
	if !ok || p.status != "pending" {
		return nil
	}
	if time.Now().After(p.expires) {
		return nil
	}
	return p
}

func (b *desktopBridge) expirePairLocked(p *bridgePair) {
	if p.status != "pending" {
		return
	}
	p.status = "expired"
	if b.pending == p.id {
		b.pending = ""
	}
	b.s.emit("bridge.pairDone", map[string]any{"id": p.id, "status": "expired"})
}

func (b *desktopBridge) sweepPairsLocked(now time.Time) {
	for id, p := range b.pairs {
		if p.status == "pending" && now.After(p.expires) {
			b.expirePairLocked(p)
		}
		if now.After(p.expires.Add(bridgePairGrace)) {
			delete(b.pairs, id)
		}
	}
}

func randomPairCode() (string, error) {
	out := make([]byte, 6)
	max := big.NewInt(int64(len(bridgePairAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = bridgePairAlphabet[n.Int64()]
	}
	return string(out), nil
}

func formatPairCode(code string) string {
	if len(code) != 6 {
		return code
	}
	return code[:3] + "-" + code[3:]
}

func (b *desktopBridge) startPair(client string) (*bridgePair, error) {
	now := time.Now()
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	code, err := randomPairCode()
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
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
		return nil, rpcErrData("cooldown", fmt.Sprintf("Too many pairing requests. Try again in %d seconds.", wait), map[string]any{"wait": wait})
	}
	b.starts = append(b.starts, now)
	b.sweepPairsLocked(now)
	if old := b.pendingPairLocked(); old != nil {
		old.status = "cancelled"
		delete(b.pairs, old.id)
		b.s.emit("bridge.pairDone", map[string]any{"id": old.id, "status": "cancelled"})
	}
	p := &bridgePair{id: hex.EncodeToString(idBytes), code: code, client: client, expires: now.Add(bridgePairTTL), status: "pending"}
	b.pairs[p.id] = p
	b.pending = p.id
	id := p.id
	time.AfterFunc(bridgePairTTL+50*time.Millisecond, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if q, ok := b.pairs[id]; ok && q.status == "pending" && time.Now().After(q.expires) {
			b.expirePairLocked(q)
		}
	})
	b.s.emit("bridge.pair", p.view())
	return p, nil
}

func (b *desktopBridge) pollPair(id string) (map[string]any, error) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pairs[id]
	if !ok || id == "" {
		return nil, rpcErr("not_found", "That pairing request does not exist. Start pairing again.")
	}
	if p.status == "pending" && now.After(p.expires) {
		b.expirePairLocked(p)
	}
	switch p.status {
	case "pending":
		return map[string]any{"status": "pending"}, nil
	case "approved":
		delete(b.pairs, id)
		if now.After(p.expires.Add(bridgePairGrace)) {
			return map[string]any{"status": "expired"}, nil
		}
		b.refreshTokenLocked()
		return map[string]any{"status": "approved", "token": b.token}, nil
	default:
		delete(b.pairs, id)
		return map[string]any{"status": p.status}, nil
	}
}

func (b *desktopBridge) respondPair(id string, allow bool) (string, string, bool, error) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pairs[id]
	if !ok || id == "" {
		return "", "", false, rpcErr("not_found", "That pairing request no longer exists.")
	}
	if p.status == "pending" && now.After(p.expires) {
		b.expirePairLocked(p)
	}
	switch p.status {
	case "expired":
		return "", p.client, false, rpcErr("pair_expired", "That pairing request expired. Start pairing again from the browser.")
	case "pending":
	default:
		return p.status, p.client, false, nil
	}
	p.status = "denied"
	if allow {
		p.status = "approved"
	}
	if b.pending == p.id {
		b.pending = ""
	}
	b.s.emit("bridge.pairDone", map[string]any{"id": p.id, "status": p.status})
	return p.status, p.client, true, nil
}

func hBridgePairRespond(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID    string `json:"id"`
		Allow bool   `json:"allow"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	status, client, changed, err := s.bridge.respondPair(strings.TrimSpace(in.ID), in.Allow)
	if err != nil {
		return nil, err
	}
	if changed {
		if client == "" {
			client = "A browser"
		}
		if status == "approved" {
			src.LogAction("BRIDGE_PAIRED", client)
		} else {
			src.LogAction("BRIDGE_PAIR_DENIED", client)
		}
	}
	return map[string]any{"ok": true, "status": status}, nil
}

func bridgeInfoRoute(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	return map[string]any{"name": "APM", "version": Version, "api": bridgeAPIVersion, "unlocked": b.s.unlocked(), "mode": b.mode}, nil
}

func bridgePairStart(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	var in struct {
		Client string `json:"client"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	client := bridgeClientName(in.Client)
	if client == "" {
		client = c.client
	}
	if client == "" {
		client = "A browser"
	}
	if b.mode == "native" {
		return b.startLinkPair(client, c.origin)
	}
	p, err := b.startPair(client)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": p.id, "code": p.code, "expires": ms(p.expires)}, nil
}

func bridgePairPoll(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	id := strings.TrimSpace(c.r.URL.Query().Get("id"))
	if b.mode == "native" {
		return b.pollLinkPair(id)
	}
	return b.pollPair(id)
}

func (s *desktopServer) bridgeStatusView() map[string]any {
	unlocked := s.unlocked()
	res := map[string]any{
		"unlocked":    unlocked,
		"readonly":    unlocked && s.isReadonly(),
		"exists":      src.VaultExists(s.vaultPath),
		"name":        "",
		"version":     Version,
		"items":       0,
		"touchId":     map[string]any{"available": s.touchIDAvailable(), "configured": s.touchIDConfigured()},
		"cooldown":    0,
		"left":        6 - src.GetFailureCount(),
		"settings":    nil,
		"spaces":      []map[string]any{},
		"activeSpace": "",
	}
	if wait := time.Until(s.cooldownUntil); wait > 0 {
		res["cooldown"] = int((wait + time.Second - 1) / time.Second)
	}
	if left := res["left"].(int); left < 0 {
		res["left"] = 0
	}
	if !unlocked {
		return res
	}
	res["name"] = s.vaultName()
	res["items"] = len(s.vault.ItemRefs())
	settings := map[string]any{}
	for _, k := range []string{"clipboard", "inactivity", "sessionTimeout"} {
		settings[k] = defaultDesktopSettings[k]
		if d := s.vault.Desktop; d != nil {
			if v, ok := d.Settings[k]; ok {
				settings[k] = v
			}
		}
	}
	res["settings"] = settings
	spaces := []map[string]any{}
	for _, sp := range s.spacesView() {
		spaces = append(spaces, map[string]any{"id": sp["id"], "name": sp["name"]})
	}
	res["spaces"] = spaces
	res["activeSpace"] = s.vault.CurrentSpace
	return res
}

func bridgeStatusRoute(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	return b.s.bridgeStatusView(), nil
}

func bridgeUnlock(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		Password string `json:"password"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if in.Password == "" {
		return nil, rpcErr("invalid", "Enter your master password.")
	}
	params, _ := json.Marshal(map[string]any{"password": in.Password})
	res, err := hVaultUnlock(s, params)
	if err != nil {
		return nil, err
	}
	s.emit("vault.unlocked", map[string]any{"snapshot": snapshotFromResult(res), "via": "browser"})
	return map[string]any{"status": s.bridgeStatusView()}, nil
}

func bridgeUnlockTouchID(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	res, err := s.unlockWithTouchID("unlock your vault for the browser extension", false)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emit("vault.unlocked", map[string]any{"snapshot": snapshotFromResult(res), "via": "browser-touchid"})
	return map[string]any{"status": s.bridgeStatusView()}, nil
}

func bridgeLock(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	reason := "Locked from the browser"
	params, _ := json.Marshal(map[string]any{"reason": reason})
	if _, err := hVaultLock(s, params); err != nil {
		return nil, err
	}
	s.emit("vault.locked", map[string]any{"reason": reason})
	return map[string]any{}, nil
}

func snapshotFromResult(res any) any {
	if m, ok := res.(map[string]any); ok {
		if snap, ok := m["snapshot"]; ok {
			return snap
		}
	}
	return nil
}

func (s *desktopServer) emitChanged(res any) {
	snap := snapshotFromResult(res)
	if snap == nil {
		snap = s.snapshot()
	}
	s.emit("vault.changed", map[string]any{"snapshot": snap})
}

func jsNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func uuidV4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
