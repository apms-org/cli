package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	src "github.com/aaravmaloo/apm/src"
	"github.com/aaravmaloo/apm/src/touchid"

	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
)

type rpcError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

func rpcErr(code, message string) *rpcError {
	return &rpcError{Code: code, Message: message}
}

func rpcErrData(code, message string, data map[string]any) *rpcError {
	return &rpcError{Code: code, Message: message, Data: data}
}

type rpcRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type desktopHandler func(s *desktopServer, p json.RawMessage) (any, error)

type desktopMethod struct {
	fn   desktopHandler
	long bool
}

type recoverState struct {
	data          []byte
	info          src.RecoveryData
	emailOK       bool
	email         string
	codeHash      [32]byte
	codeSent      time.Time
	codeAttempts  int
	codeVerified  bool
	keyAttempts   int
	dek           []byte
	via           string
	secondOK      bool
	usedCodeIndex int
}

type emailSetupState struct {
	email    string
	codeHash [32]byte
	sent     time.Time
	attempts int
}

type frameQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	w      io.Writer
	active bool
}

func newFrameQueue(w io.Writer) *frameQueue {
	q := &frameQueue{w: w}
	q.cond = sync.NewCond(&q.mu)
	go q.run()
	return q
}

func (q *frameQueue) push(b []byte) {
	q.mu.Lock()
	q.queue = append(q.queue, b)
	q.mu.Unlock()
	q.cond.Broadcast()
}

func (q *frameQueue) run() {
	for {
		q.mu.Lock()
		for len(q.queue) == 0 {
			q.cond.Wait()
		}
		next := q.queue[0]
		q.queue = q.queue[1:]
		q.active = true
		q.mu.Unlock()
		_, _ = q.w.Write(next)
		q.mu.Lock()
		q.active = false
		q.mu.Unlock()
		q.cond.Broadcast()
	}
}

func (q *frameQueue) flush(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		done := len(q.queue) == 0 && !q.active
		q.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type desktopServer struct {
	mu            sync.Mutex
	frames        *frameQueue
	vaultPath     string
	password      string
	vault         *src.Vault
	readonlyUntil time.Time
	lastWriteHash string
	cooldownUntil time.Time
	wrongStreak   int
	rec           *recoverState
	emailSetup    *emailSetupState
	diffs         map[string][]src.VaultDiffChange
	knownTx       map[string]bool
	touchAvail    int
	touchConf     int
	autoSync      *time.Timer
	watchTimer    *time.Timer
	bridge        *desktopBridge
}

func newDesktopCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "desktop",
		Short:  "Run the APM desktop backend over stdio",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			protocolOut := os.Stdout
			os.Stdout = os.Stderr
			color.Output = os.Stderr
			color.Error = os.Stderr
			if err := runDesktopServer(protocolOut, os.Stdin); err != nil {
				fmt.Fprintf(os.Stderr, "desktop backend stopped: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

func runDesktopServer(out io.Writer, in io.Reader) error {
	abs, err := filepath.Abs(vaultPath)
	if err == nil {
		vaultPath = filepath.Clean(abs)
	}
	if strings.TrimSpace(os.Getenv("APM_STATE_DIR")) == "" {
		_ = os.Setenv("APM_STATE_DIR", filepath.Dir(vaultPath))
	}
	_ = os.MkdirAll(filepath.Dir(vaultPath), 0700)
	_ = os.Chdir(filepath.Dir(vaultPath))

	s := &desktopServer{
		frames:     newFrameQueue(out),
		vaultPath:  vaultPath,
		diffs:      map[string][]src.VaultDiffChange{},
		knownTx:    map[string]bool{},
		touchAvail: -1,
		touchConf:  -1,
	}
	s.bridge = newDesktopBridge(s)
	s.bridge.start()
	s.startWatcher()
	go s.pollMCP()

	reader := bufio.NewReaderSize(in, 1<<20)
	for {
		line, err := reader.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			s.dispatch(line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.shutdown()
				s.frames.flush(5 * time.Second)
				return nil
			}
			return err
		}
	}
}

func (s *desktopServer) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropKey()
	if s.bridge != nil {
		s.bridge.stop()
	}
}

func (s *desktopServer) dispatch(line []byte) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		s.writeFrame(map[string]any{"id": nil, "error": rpcErr("invalid", "Malformed request.")})
		return
	}
	m, ok := desktopMethods[req.Method]
	if !ok {
		s.respond(req.ID, nil, rpcErr("unsupported", "Unknown method "+req.Method+"."))
		return
	}
	run := func() {
		defer func() {
			if r := recover(); r != nil {
				s.respond(req.ID, nil, rpcErr("internal", fmt.Sprintf("Internal error: %v", r)))
			}
		}()
		if m.long {
			res, err := m.fn(s, req.Params)
			s.respond(req.ID, res, err)
			return
		}
		s.mu.Lock()
		res, err := func() (any, error) {
			defer s.mu.Unlock()
			return m.fn(s, req.Params)
		}()
		s.respond(req.ID, res, err)
	}
	if m.long {
		go run()
	} else {
		run()
	}
}

func (s *desktopServer) respond(id json.RawMessage, result any, err error) {
	frame := map[string]any{"id": id}
	if len(id) == 0 {
		frame["id"] = nil
	}
	if err != nil {
		var re *rpcError
		if !errors.As(err, &re) {
			re = mapGoError(err)
		}
		frame["error"] = re
	} else {
		if result == nil {
			result = map[string]any{"ok": true}
		}
		frame["result"] = result
	}
	s.writeFrame(frame)
}

func mapGoError(err error) *rpcError {
	switch {
	case errors.Is(err, src.ErrItemExists):
		return rpcErr("exists", err.Error())
	case errors.Is(err, src.ErrItemNotFound):
		return rpcErr("not_found", err.Error())
	case errors.Is(err, src.ErrItemInvalid):
		return rpcErr("invalid", strings.TrimPrefix(err.Error(), src.ErrItemInvalid.Error()+": "))
	case errors.Is(err, os.ErrNotExist):
		return rpcErr("not_found", err.Error())
	}
	return rpcErr("internal", err.Error())
}

func (s *desktopServer) writeFrame(frame any) {
	data, err := json.Marshal(frame)
	if err != nil {
		data, _ = json.Marshal(map[string]any{"event": "backend.error", "data": map[string]any{"message": err.Error()}})
	}
	s.frames.push(append(data, '\n'))
}

func (s *desktopServer) emit(event string, data any) {
	s.writeFrame(map[string]any{"event": event, "data": data})
}

func decodeParams(p json.RawMessage, v any) error {
	if len(p) == 0 || string(p) == "null" {
		return nil
	}
	if err := json.Unmarshal(p, v); err != nil {
		return rpcErr("invalid", "Invalid parameters: "+err.Error())
	}
	return nil
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *desktopServer) unlocked() bool {
	return s.vault != nil && s.password != ""
}

func (s *desktopServer) isReadonly() bool {
	if s.readonlyUntil.IsZero() {
		return false
	}
	if time.Now().After(s.readonlyUntil) {
		s.readonlyUntil = time.Time{}
		return false
	}
	return true
}

func (s *desktopServer) requireUnlocked() error {
	if !s.unlocked() {
		return rpcErr("locked", "The vault is locked.")
	}
	return nil
}

func (s *desktopServer) requireWritable() error {
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	if s.isReadonly() {
		return rpcErr("readonly", "This session is read-only.")
	}
	return nil
}

func (s *desktopServer) desktop() *src.DesktopState {
	if s.vault.Desktop == nil {
		s.vault.Desktop = &src.DesktopState{}
	}
	return s.vault.Desktop
}

func (s *desktopServer) dropKey() {
	s.vault = nil
	s.password = ""
	s.readonlyUntil = time.Time{}
	s.diffs = map[string][]src.VaultDiffChange{}
	s.emailSetup = nil
	if s.autoSync != nil {
		s.autoSync.Stop()
		s.autoSync = nil
	}
}

func (s *desktopServer) writeVault(data []byte, recordCommit bool, note string) error {
	hash := sha256Hex(data)
	s.lastWriteHash = hash
	if recordCommit {
		if err := src.SaveVault(s.vaultPath, data); err != nil {
			return err
		}
		if note != "" {
			if head, err := src.GetLGitHead(); err == nil && head != nil && head.DataHash == hash {
				_ = src.SetLGitNote(head.ID, note)
			}
		}
		return nil
	}
	return os.WriteFile(s.vaultPath, data, 0600)
}

func (s *desktopServer) save(note string) error {
	data, err := src.EncryptVault(s.vault, s.password)
	if err != nil {
		return err
	}
	if err := s.writeVault(data, true, note); err != nil {
		return err
	}
	s.scheduleAutoSync()
	return nil
}

func (s *desktopServer) saveQuiet() error {
	data, err := src.EncryptVault(s.vault, s.password)
	if err != nil {
		return err
	}
	return s.writeVault(data, false, "")
}

func (s *desktopServer) withSnapshot(result map[string]any) map[string]any {
	if result == nil {
		result = map[string]any{}
	}
	if _, ok := result["ok"]; !ok {
		result["ok"] = true
	}
	result["snapshot"] = s.snapshot()
	return result
}

func (s *desktopServer) reloadFromDisk() error {
	data, err := os.ReadFile(s.vaultPath)
	if err != nil {
		return err
	}
	s.lastWriteHash = sha256Hex(data)
	v, err := src.DecryptVault(data, s.password, 1)
	if err != nil {
		s.dropKey()
		s.emit("vault.locked", map[string]any{"reason": "The restored vault uses a different master password. Unlock it again."})
		return rpcErr("locked", "The restored vault uses a different master password. Unlock it again.")
	}
	s.vault = v
	return nil
}

func (s *desktopServer) touchIDDisabled() bool {
	return strings.TrimSpace(os.Getenv("APM_DESKTOP_NO_TOUCHID")) != ""
}

func (s *desktopServer) touchIDAvailable() bool {
	if s.touchIDDisabled() || runtime.GOOS != "darwin" {
		return false
	}
	if s.touchAvail < 0 {
		if touchid.IsAvailable() {
			s.touchAvail = 1
		} else {
			s.touchAvail = 0
		}
	}
	return s.touchAvail == 1
}

func (s *desktopServer) touchIDConfigured() bool {
	if s.touchIDDisabled() || runtime.GOOS != "darwin" {
		return false
	}
	if s.touchConf < 0 {
		if touchid.IsConfigured() {
			s.touchConf = 1
		} else {
			s.touchConf = 0
		}
	}
	return s.touchConf == 1
}

func (s *desktopServer) startWatcher() {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	if err := w.Add(filepath.Dir(s.vaultPath)); err != nil {
		w.Close()
		return
	}
	go func() {
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(ev.Name) != s.vaultPath {
					continue
				}
				s.mu.Lock()
				if s.watchTimer != nil {
					s.watchTimer.Stop()
				}
				s.watchTimer = time.AfterFunc(300*time.Millisecond, s.onVaultFileChanged)
				s.mu.Unlock()
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()
}

func (s *desktopServer) onVaultFileChanged() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.unlocked() {
		return
	}
	data, err := os.ReadFile(s.vaultPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.dropKey()
			s.emit("vault.locked", map[string]any{"reason": "The vault file was removed."})
		}
		return
	}
	hash := sha256Hex(data)
	if hash == s.lastWriteHash {
		return
	}
	v, err := src.DecryptVault(data, s.password, 1)
	if err != nil {
		s.dropKey()
		s.emit("vault.locked", map[string]any{"reason": "The vault was re-encrypted with a different master password."})
		return
	}
	s.lastWriteHash = hash
	s.vault = v
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
}

func (s *desktopServer) pollMCP() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		if s.unlocked() {
			txs, err := src.ListMCPTransactions(50)
			if err == nil {
				for _, tx := range txs {
					if tx.Status != "pending" || s.knownTx[tx.ID] {
						continue
					}
					s.knownTx[tx.ID] = true
					s.emit("mcp.pending", map[string]any{"tx": mcpTxView(tx)})
				}
			}
		}
		s.mu.Unlock()
	}
}

func (s *desktopServer) markKnownTx() {
	txs, err := src.ListMCPTransactions(0)
	if err != nil {
		return
	}
	for _, tx := range txs {
		s.knownTx[tx.ID] = true
	}
}

var defaultDesktopSettings = map[string]any{
	"sessionTimeout": "60",
	"inactivity":     "15",
	"lockOnSleep":    true,
	"clipboard":      "30",
	"copyOnClick":    true,
	"confirmDelete":  true,
	"showTypeIcons":  true,
	"openOnLaunch":   "all",
}

func displayCipher(c string) string {
	if src.NormalizeCipherName(c) == src.CipherXChaCha20Poly1305 {
		return "XChaCha20-Poly1305"
	}
	return "AES-256-GCM"
}

func displayKDF(k string) string {
	if strings.EqualFold(k, "pbkdf2") {
		return "PBKDF2"
	}
	return "Argon2id"
}

func builtinProfileName(p src.CryptoProfile) string {
	for _, name := range []string{"standard", "hardened", "paranoid", "legacy"} {
		b := src.Profiles[name]
		if strings.EqualFold(b.KDF, p.KDF) && b.Time == p.Time && b.Memory == p.Memory && b.Parallelism == p.Parallelism && b.SaltLen == p.SaltLen {
			return name
		}
	}
	return "custom"
}

func profileView(p src.CryptoProfile) map[string]any {
	return map[string]any{
		"name":    builtinProfileName(p),
		"kdf":     displayKDF(p.KDF),
		"time":    p.Time,
		"memory":  p.Memory / 1024,
		"threads": p.Parallelism,
		"cipher":  displayCipher(p.Cipher),
	}
}

func customView(p src.CryptoProfile) map[string]any {
	return map[string]any{
		"name":     "Custom",
		"kdf":      displayKDF(p.KDF),
		"time":     p.Time,
		"memory":   p.Memory / 1024,
		"threads":  p.Parallelism,
		"saltLen":  p.SaltLen,
		"nonceLen": p.NonceLen,
		"cipher":   displayCipher(p.Cipher),
	}
}

type customProfileParams struct {
	Name     string `json:"name"`
	KDF      string `json:"kdf"`
	Time     uint32 `json:"time"`
	Memory   uint32 `json:"memory"`
	Threads  uint8  `json:"threads"`
	SaltLen  int    `json:"saltLen"`
	NonceLen int    `json:"nonceLen"`
	Cipher   string `json:"cipher"`
}

func buildCryptoProfile(name string, custom *customProfileParams, cipher string) (src.CryptoProfile, string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "standard"
	}
	var p src.CryptoProfile
	switch name {
	case "standard", "hardened", "paranoid":
		p = src.GetProfile(name)
	case "legacy":
		return p, "", rpcErr("invalid", "The legacy profile can only be set from the CLI.")
	case "custom":
		if custom == nil {
			return p, "", rpcErr("invalid", "Custom profile parameters are missing.")
		}
		if custom.Time < 1 || custom.Time > 20 {
			return p, "", rpcErr("invalid", "Time cost must be between 1 and 20.")
		}
		if custom.Memory < 8 || custom.Memory > 4096 {
			return p, "", rpcErr("invalid", "Memory must be between 8 and 4096 MiB.")
		}
		if custom.Threads < 1 || custom.Threads > 32 {
			return p, "", rpcErr("invalid", "Threads must be between 1 and 32.")
		}
		salt := custom.SaltLen
		if salt == 0 {
			salt = 16
		}
		if salt < 16 || salt > 64 {
			return p, "", rpcErr("invalid", "Salt length must be between 16 and 64 bytes.")
		}
		p = src.CryptoProfile{Name: "custom", KDF: "argon2id", Time: custom.Time, Memory: custom.Memory * 1024, Parallelism: custom.Threads, SaltLen: salt, NonceLen: custom.NonceLen}
		if cipher == "" {
			cipher = custom.Cipher
		}
	default:
		return p, "", rpcErr("invalid", "Unknown profile "+name+".")
	}
	if strings.TrimSpace(cipher) != "" {
		c := src.NormalizeCipherName(cipher)
		if c == "" {
			return p, "", rpcErr("invalid", "Unknown cipher "+cipher+".")
		}
		p.Cipher = c
	}
	if p.Cipher == src.CipherXChaCha20Poly1305 {
		p.NonceLen = 24
	} else if p.NonceLen <= 0 {
		p.NonceLen = 12
	} else if p.NonceLen != 12 && p.NonceLen != 24 {
		return p, "", rpcErr("invalid", "Nonce length must be 12 or 24 bytes.")
	}
	p = src.NormalizeCryptoProfile(p)
	return p, name, nil
}

func (s *desktopServer) vaultName() string {
	if s.vault != nil && s.vault.Desktop != nil && strings.TrimSpace(s.vault.Desktop.Name) != "" {
		return s.vault.Desktop.Name
	}
	return "Personal vault"
}

func (s *desktopServer) isFavorite(id string) bool {
	if s.vault.Desktop == nil {
		return false
	}
	for _, f := range s.vault.Desktop.Favorites {
		if f == id {
			return true
		}
	}
	return false
}

func (s *desktopServer) setFavorite(id string, on bool) {
	d := s.desktop()
	out := d.Favorites[:0:0]
	for _, f := range d.Favorites {
		if f != id {
			out = append(out, f)
		}
	}
	if on {
		out = append(out, id)
	}
	d.Favorites = out
}

func (s *desktopServer) renameID(oldID, newID string) {
	if oldID == newID || s.vault.Desktop == nil {
		return
	}
	d := s.vault.Desktop
	for i, f := range d.Favorites {
		if f == oldID {
			d.Favorites[i] = newID
		}
	}
	if d.Versions != nil {
		if list, ok := d.Versions[oldID]; ok {
			delete(d.Versions, oldID)
			d.Versions[newID] = list
		}
	}
}

func (s *desktopServer) remapByIndex(before []src.VaultItemRef, removedType string, removedIndex int) {
	after := s.vault.ItemRefs()
	byKey := map[string]string{}
	for _, a := range after {
		byKey[a.Spec.ID+"#"+strconv.Itoa(a.Index)] = a.ID
	}
	mapping := map[string]string{}
	for _, b := range before {
		idx := b.Index
		if b.Spec.ID == removedType {
			if idx == removedIndex {
				continue
			}
			if idx > removedIndex && removedIndex >= 0 {
				idx--
			}
		}
		if newID, ok := byKey[b.Spec.ID+"#"+strconv.Itoa(idx)]; ok && newID != b.ID {
			mapping[b.ID] = newID
		}
	}
	if len(mapping) == 0 || s.vault.Desktop == nil {
		return
	}
	d := s.vault.Desktop
	for i, f := range d.Favorites {
		if n, ok := mapping[f]; ok {
			d.Favorites[i] = n
		}
	}
	if d.Versions != nil {
		moved := map[string][]src.ItemVersion{}
		for oldID, list := range d.Versions {
			if n, ok := mapping[oldID]; ok {
				moved[n] = list
				delete(d.Versions, oldID)
			}
		}
		for k, v := range moved {
			d.Versions[k] = v
		}
	}
}

func parseJSTime(s *string) int64 {
	if s == nil || *s == "" {
		return 0
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return t.UnixMilli()
		}
	}
	return 0
}

func passkeyViews(list []src.Passkey) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, p := range list {
		created := p.CreatedAt
		out = append(out, map[string]any{
			"id":              p.ID,
			"rpId":            p.RPID,
			"userName":        p.UserName,
			"userDisplayName": p.UserDisplayName,
			"credentialId":    p.CredentialID,
			"signCount":       p.SignCount,
			"createdAt":       parseJSTime(&created),
			"lastUsedAt":      parseJSTime(p.LastUsedAt),
			"label":           p.Label,
		})
	}
	return out
}

func (s *desktopServer) versionsFor(id string) []map[string]any {
	out := []map[string]any{}
	if s.vault.Desktop == nil || s.vault.Desktop.Versions == nil {
		return out
	}
	for _, ver := range s.vault.Desktop.Versions[id] {
		out = append(out, map[string]any{"f": ver.F, "ts": ms(ver.TS)})
	}
	return out
}

func telemetryFields(t src.SecretTelemetry) map[string]any {
	priv := t.Privilege
	if priv == "standard" {
		priv = ""
	}
	return map[string]any{
		"created":   ms(t.CreatedAt),
		"modified":  ms(t.UpdatedAt),
		"used":      ms(t.LastAccessed),
		"uses":      t.AccessCount,
		"rotated":   ms(t.LastRotation),
		"createdBy": t.CreatedBy,
		"source":    t.Source,
		"privilege": priv,
		"exposed":   t.Exposed,
	}
}

func (s *desktopServer) itemView(ref src.VaultItemRef) map[string]any {
	item := telemetryFields(s.vault.ItemTelemetry(ref))
	item["id"] = ref.ID
	item["type"] = ref.Spec.ID
	item["space"] = ref.Space
	item["fav"] = s.isFavorite(ref.ID)
	item["f"] = s.vault.ItemRecordFields(ref)
	item["passkeys"] = passkeyViews(s.vault.ItemPasskeys(ref))
	item["versions"] = s.versionsFor(ref.ID)
	return item
}

func (s *desktopServer) trashView(t src.TrashedItem) map[string]any {
	var tel src.SecretTelemetry
	if t.Telemetry != nil {
		tel = *t.Telemetry
	}
	item := telemetryFields(tel)
	item["id"] = t.ID
	item["type"] = t.Type
	item["space"] = t.Space
	item["fav"] = t.Favorite
	item["f"] = t.Fields()
	item["passkeys"] = passkeyViews(t.Passkeys())
	item["versions"] = s.versionsFor(t.ID)
	item["deletedAt"] = ms(t.DeletedAt)
	return item
}

func (s *desktopServer) itemByID(id string) (map[string]any, bool) {
	ref, ok := s.vault.FindItem(id)
	if !ok {
		return nil, false
	}
	return s.itemView(ref), true
}

func (s *desktopServer) spacesView() []map[string]any {
	out := []map[string]any{}
	d := s.vault.Desktop
	i := 0
	for _, name := range s.vault.Spaces {
		if strings.TrimSpace(name) == "" || strings.EqualFold(name, "default") {
			continue
		}
		color := i % 7
		var created time.Time
		if d != nil {
			if c, ok := d.SpaceColors[name]; ok {
				color = c
			}
			created = d.SpaceCreated[name]
		}
		out = append(out, map[string]any{"id": name, "name": name, "color": color, "created": ms(created)})
		i++
	}
	return out
}

func (s *desktopServer) spaceExists(name string) (string, bool) {
	for _, sp := range s.vault.Spaces {
		if strings.EqualFold(sp, name) {
			return sp, true
		}
	}
	return "", false
}

func normalizeSpaceParam(space string) string {
	space = strings.TrimSpace(space)
	if strings.EqualFold(space, "default") {
		return ""
	}
	return space
}

func (s *desktopServer) ensureSpace(space string) string {
	if space == "" {
		return ""
	}
	if existing, ok := s.spaceExists(space); ok {
		return existing
	}
	if len(s.vault.Spaces) == 0 {
		s.vault.Spaces = []string{"default"}
	}
	s.vault.Spaces = append(s.vault.Spaces, space)
	d := s.desktop()
	if d.SpaceCreated == nil {
		d.SpaceCreated = map[string]time.Time{}
	}
	d.SpaceCreated[space] = time.Now()
	return space
}

func auditView(logs []src.AuditEntry) []map[string]any {
	verified := src.VerifyAuditLogs(logs)
	out := []map[string]any{}
	for i := len(logs) - 1; i >= 0 && len(out) < 500; i-- {
		a := logs[i]
		id := a.Hash
		if len(id) > 12 {
			id = id[:12]
		}
		if id == "" {
			id = "a" + strconv.Itoa(i)
		}
		who := a.User
		if a.Hostname != "" {
			who = a.User + "@" + a.Hostname
		}
		ok := i < len(verified) && verified[i]
		out = append(out, map[string]any{"id": id, "ts": ms(a.Timestamp), "action": a.Action, "details": a.Details, "who": who, "verified": ok})
	}
	return out
}

func historyView(v *src.Vault) []map[string]any {
	verified := src.VerifyHistoryChain(v)
	out := []map[string]any{}
	for i := len(v.History) - 1; i >= 0 && len(out) < 500; i-- {
		h := v.History[i]
		category := strings.ToLower(h.Category)
		if spec, ok := src.ItemTypeByCategory(h.Category); ok {
			category = spec.ID
		}
		ok := i < len(verified) && verified[i]
		out = append(out, map[string]any{"ts": ms(h.Timestamp), "action": h.Action, "category": category, "identifier": h.Identifier, "verified": ok})
	}
	return out
}

func (s *desktopServer) commitsView() ([]map[string]any, string) {
	commits, err := src.GetLGitCommits(0)
	if err != nil {
		return []map[string]any{}, ""
	}
	verified := src.VerifyLGitCommits(commits)
	notes := src.LGitNotes()
	out := []map[string]any{}
	head := ""
	for i := len(commits) - 1; i >= 0; i-- {
		c := commits[i]
		if c.VaultPath != "" && filepath.Clean(c.VaultPath) != s.vaultPath {
			continue
		}
		if head == "" {
			head = c.ID
		}
		if len(out) >= 200 {
			continue
		}
		var size int64
		exists := false
		if c.SnapshotFile != "" {
			if st, err := os.Stat(c.SnapshotFile); err == nil {
				size = st.Size()
				exists = true
			}
		}
		out = append(out, map[string]any{
			"id":       c.ID,
			"ts":       ms(c.Timestamp),
			"action":   c.Action,
			"note":     notes[c.ID],
			"dataHash": c.DataHash,
			"prevHash": c.PrevHash,
			"hash":     c.Hash,
			"verified": i < len(verified) && verified[i],
			"bytes":    size,
			"snapshot": exists,
		})
	}
	return out, head
}

func (s *desktopServer) recoveryView() map[string]any {
	v := s.vault
	d := v.Desktop
	var keyCreated, codesCreated time.Time
	if d != nil {
		keyCreated = d.RecoveryKeyCreated
		codesCreated = d.RecoveryCodesCreated
	}
	var quorum any
	if v.RecoveryShareThreshold >= 2 && len(v.RecoveryShareHashes) > 0 {
		quorum = map[string]any{"threshold": v.RecoveryShareThreshold, "shares": v.RecoveryShareCount}
	}
	return map[string]any{
		"email":         src.MaskEmailHint(v.RecoveryEmail),
		"emailVerified": v.RecoveryEmail != "",
		"key":           len(v.RecoveryHash) > 0 && len(v.RecoverySlot) > 0,
		"keyCreated":    ms(keyCreated),
		"codes":         map[string]any{"total": len(v.RecoveryCodeHashes), "unused": src.CountRemainingRecoveryCodes(v)},
		"codesCreated":  ms(codesCreated),
		"passkey":       v.RecoveryPasskeyEnabled && len(v.RecoveryPasskeyCred) > 0,
		"quorum":        quorum,
	}
}

func (s *desktopServer) ignoreInfo() (string, string) {
	_, path, _ := src.LoadIgnoreConfigForVault(s.vaultPath)
	if path == "" {
		path = filepath.Join(filepath.Dir(s.vaultPath), src.APMIgnoreFileName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", path
	}
	return string(data), path
}

func (s *desktopServer) providerConnected(provider string) bool {
	v := s.vault
	switch provider {
	case "github":
		return v.GitHubToken != "" && v.GitHubRepo != ""
	case "gdrive":
		return v.CloudFileID != ""
	case "dropbox":
		return len(v.DropboxToken) > 0 && v.DropboxFileID != ""
	}
	return false
}

func (s *desktopServer) syncView() map[string]any {
	v := s.vault
	d := v.Desktop
	var lastAll time.Time
	providers := []map[string]any{}
	for _, id := range []string{"github", "gdrive", "dropbox"} {
		p := map[string]any{"id": id, "connected": s.providerConnected(id), "mode": "", "repo": "", "fileId": "", "retrieval": false, "retrievalKey": "", "last": int64(0), "state": "idle", "error": ""}
		switch id {
		case "github":
			p["mode"] = "pat"
			p["repo"] = v.GitHubRepo
		case "gdrive":
			p["mode"] = v.DriveSyncMode
			p["fileId"] = v.CloudFileID
			if v.CloudFileID != "" && v.RetrievalKey != "" && (v.LastCloudProvider == "gdrive" || v.DropboxFileID == "") {
				p["retrieval"] = true
				p["retrievalKey"] = v.RetrievalKey
			}
		case "dropbox":
			p["mode"] = v.DropboxSyncMode
			p["fileId"] = v.DropboxFileID
			if v.DropboxFileID != "" && v.RetrievalKey != "" && (v.LastCloudProvider == "dropbox" || v.CloudFileID == "") {
				p["retrieval"] = true
				p["retrievalKey"] = v.RetrievalKey
			}
		}
		if d != nil {
			if t, ok := d.SyncLast[id]; ok {
				p["last"] = ms(t)
				if t.After(lastAll) {
					lastAll = t
				}
				p["state"] = "ok"
			}
			if e := d.SyncError[id]; e != "" {
				p["state"] = "error"
				p["error"] = e
			}
		}
		providers = append(providers, p)
	}
	ignore, ignorePath := s.ignoreInfo()
	auto := false
	if d != nil {
		auto = d.SyncAuto
	}
	return map[string]any{"providers": providers, "auto": auto, "lastSync": ms(lastAll), "pending": false, "ignore": ignore, "ignorePath": ignorePath}
}

func mcpTokenID(token string) string {
	return sha256Hex([]byte(token))[:12]
}

func mcpTokenViews() []map[string]any {
	list, _ := src.ListMCPTokens()
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	out := []map[string]any{}
	for _, t := range list {
		prefix := t.Token
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		perms := t.Permissions
		if perms == nil {
			perms = []string{}
		}
		out = append(out, map[string]any{
			"id":       mcpTokenID(t.Token),
			"name":     t.Name,
			"prefix":   prefix,
			"perms":    perms,
			"created":  ms(t.CreatedAt),
			"expires":  ms(t.ExpiresAt),
			"lastUsed": ms(t.LastUsedAt),
			"uses":     t.UsageCount,
		})
	}
	return out
}

var mcpTypeToItemType = map[string]string{
	"password": "password", "totp": "totp", "token": "token", "note": "note", "api_key": "apikey", "ssh_key": "ssh_key",
	"wifi": "wifi", "recovery_code": "recovery", "certificate": "certificate", "banking": "banking", "document": "document",
	"gov_id": "govid", "medical": "medical", "travel": "travel", "contact": "contact", "cloud": "cloud", "k8s_secret": "k8s",
	"docker": "docker", "ssh_config": "ssh_config", "cicd": "cicd", "license": "license", "contract": "legal",
	"audio": "audio", "video": "video", "photo": "photo",
}

func mcpTxView(tx src.MCPTransaction) map[string]any {
	status := tx.Status
	switch status {
	case "committed":
		status = "approved"
	case "aborted":
		status = "rejected"
	}
	if status == "pending" && time.Now().After(tx.ExpiresAt) {
		status = "expired"
	}
	var args map[string]any
	_ = json.Unmarshal(tx.Args, &args)
	entry := map[string]any{}
	f := map[string]any{}
	for k, v := range args {
		switch k {
		case "tx_id", "approve":
			continue
		case "type":
			if t, ok := mcpTypeToItemType[toStr(v)]; ok {
				entry["type"] = t
			} else {
				entry["type"] = toStr(v)
			}
		case "name":
			entry["name"] = v
			f[k] = v
		case "space":
			entry["space"] = v
		case "password", "secret", "key", "token_val", "cvv", "secret_key", "serial_key", "content", "id_number", "details":
			if s := toStr(v); s != "" {
				f[k] = "••••••"
			}
		default:
			f[k] = v
		}
	}
	entry["f"] = f
	return map[string]any{
		"id":      tx.ID,
		"client":  tx.TokenName,
		"op":      tx.Tool,
		"summary": tx.Preview,
		"entry":   entry,
		"created": ms(tx.CreatedAt),
		"expires": ms(tx.ExpiresAt),
		"status":  status,
		"receipt": tx.Receipt,
	}
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func (s *desktopServer) mcpView() map[string]any {
	d := s.vault.Desktop
	enabled := false
	clients := map[string]bool{}
	if d != nil {
		enabled = d.MCPEnabled
		for k, v := range d.MCPClients {
			clients[k] = v
		}
	}
	txs, _ := src.ListMCPTransactions(100)
	txList := []map[string]any{}
	for _, tx := range txs {
		txList = append(txList, mcpTxView(tx))
	}
	return map[string]any{"enabled": enabled, "clients": clients, "tokens": mcpTokenViews(), "tx": txList}
}

func sessionsView() []map[string]any {
	list, _ := src.ListEphemeralSessions()
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	out := []map[string]any{}
	for _, e := range list {
		out = append(out, map[string]any{
			"id":       e.ID,
			"label":    e.Label,
			"agent":    e.BoundAgent,
			"scope":    e.Scope,
			"created":  ms(e.CreatedAt),
			"expires":  ms(e.ExpiresAt),
			"bindHost": e.BoundHostHash != "",
			"bindPid":  e.BoundPID > 0,
			"revoked":  e.Revoked,
		})
	}
	return out
}

func cliSessionView() map[string]any {
	sess, err := src.PeekSession()
	if err != nil || sess == nil {
		return map[string]any{"active": false, "expires": int64(0), "lastUsed": int64(0), "readonly": false, "inactivity": int64(0)}
	}
	return map[string]any{"active": true, "expires": ms(sess.Expiry), "lastUsed": ms(sess.LastUsed), "readonly": sess.ReadOnly, "inactivity": sess.InactivityTimeout.Milliseconds()}
}

func (s *desktopServer) policyDir() string {
	return filepath.Join(filepath.Dir(s.vaultPath), "policies")
}

func (s *desktopServer) policiesView() []map[string]any {
	list, _ := src.LoadPolicies(s.policyDir())
	out := []map[string]any{}
	for _, p := range list {
		out = append(out, map[string]any{
			"name":              p.Name,
			"min_length":        p.PasswordPolicy.MinLength,
			"require_uppercase": p.PasswordPolicy.RequireUpper,
			"require_numbers":   p.PasswordPolicy.RequireNumbers,
			"require_symbols":   p.PasswordPolicy.RequireSymbols,
			"rotate_every_days": p.RotationPolicy.RotateEveryDays,
		})
	}
	return out
}

func (s *desktopServer) totpOrderView(refs []src.VaultItemRef) []string {
	byKey := map[string]string{}
	for _, r := range refs {
		if r.Spec.ID == "totp" {
			byKey[s.vault.TOTPOrderKey(r)] = r.ID
		}
	}
	out := []string{}
	for _, k := range s.vault.TOTPOrder {
		if id, ok := byKey[strings.ToLower(strings.TrimSpace(k))]; ok {
			out = append(out, id)
		}
	}
	return out
}

func (s *desktopServer) createdTime() time.Time {
	if d := s.vault.Desktop; d != nil && !d.Created.IsZero() {
		return d.Created
	}
	if len(s.vault.History) > 0 {
		return s.vault.History[0].Timestamp
	}
	return time.Time{}
}

func (s *desktopServer) snapshot() map[string]any {
	v := s.vault
	var modified time.Time
	if st, err := os.Stat(s.vaultPath); err == nil {
		modified = st.ModTime()
	}
	params := src.GetProfile(v.Profile)
	if v.CurrentProfileParams != nil {
		params = *v.CurrentProfileParams
	}
	profile := builtinProfileName(params)
	var custom any
	if profile == "custom" {
		custom = customView(params)
	}
	level := v.SecurityLevel
	if level < 1 {
		level = 1
	}
	refs := v.ItemRefs()
	items := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		items = append(items, s.itemView(r))
	}
	trash := []map[string]any{}
	settings := map[string]any{}
	for k, val := range defaultDesktopSettings {
		settings[k] = val
	}
	if d := v.Desktop; d != nil {
		for _, t := range d.Trash {
			trash = append(trash, s.trashView(t))
		}
		for k, val := range d.Settings {
			settings[k] = val
		}
	}
	logs, _ := src.GetAuditLogs(0)
	commits, head := s.commitsView()
	return map[string]any{
		"v": 4,
		"meta": map[string]any{
			"name":          s.vaultName(),
			"path":          s.vaultPath,
			"created":       ms(s.createdTime()),
			"modified":      ms(modified),
			"profile":       profile,
			"custom":        custom,
			"cipher":        displayCipher(params.Cipher),
			"securityLevel": level,
			"alerts":        v.AlertsEnabled,
			"alertEmail":    v.AlertEmail,
			"anomaly":       v.AnomalyDetectionEnabled,
			"policy":        v.ActivePolicy.Name,
			"activeSpace":   v.CurrentSpace,
			"version":       Version,
		},
		"auth":       map[string]any{"touchId": s.touchIDConfigured(), "touchIdAvailable": s.touchIDAvailable()},
		"items":      items,
		"spaces":     s.spacesView(),
		"trash":      trash,
		"audit":      auditView(logs),
		"history":    historyView(v),
		"commits":    commits,
		"head":       head,
		"settings":   settings,
		"bridge":     s.bridge.info(),
		"recovery":   s.recoveryView(),
		"sync":       s.syncView(),
		"mcp":        s.mcpView(),
		"sessions":   sessionsView(),
		"cliSession": cliSessionView(),
		"policies":   s.policiesView(),
		"totpOrder":  s.totpOrderView(refs),
		"readonly":   s.isReadonly(),
	}
}

func (s *desktopServer) scheduleAutoSync() {
	if s.vault == nil || s.vault.Desktop == nil || !s.vault.Desktop.SyncAuto {
		return
	}
	any := false
	for _, p := range []string{"github", "gdrive", "dropbox"} {
		if s.providerConnected(p) {
			any = true
		}
	}
	if !any {
		return
	}
	if s.autoSync != nil {
		s.autoSync.Stop()
	}
	s.autoSync = time.AfterFunc(2*time.Second, func() {
		_, _ = s.syncNow("", true)
	})
}

var auditActionPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,47}$`)

func maskSecret(v string) string {
	if v == "" {
		return ""
	}
	r := []rune(v)
	if len(r) <= 4 {
		return "••••"
	}
	return string(r[:2]) + "••••" + string(r[len(r)-2:])
}
