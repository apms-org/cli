package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	src "github.com/aaravmaloo/apm/src"
)

const defaultBridgePort = 41417

type bridgeEntryType struct {
	vaultKey string
	label    string
}

var bridgeEntryTypes = []bridgeEntryType{
	{"entries", "Password"},
	{"totp_entries", "TOTP"},
	{"tokens", "Token"},
	{"api_keys", "API Key"},
	{"ssh_keys", "SSH Key"},
	{"ssh_configs", "SSH Config"},
	{"secure_notes", "Secure Note"},
	{"cloud_credentials_items", "Cloud Creds"},
	{"wifi_credentials", "Wi-Fi"},
	{"banking_items", "Banking"},
	{"k8s_secrets", "Kubernetes"},
	{"docker_registries", "Docker"},
	{"cicd_secrets", "CI/CD"},
	{"software_licenses", "License"},
	{"legal_contracts", "Legal"},
	{"gov_ids", "Gov ID"},
	{"medical_records", "Medical"},
	{"travel_docs", "Travel"},
	{"contacts", "Contact"},
	{"recovery_codes", "Recovery"},
}

type desktopBridge struct {
	s       *desktopServer
	mu      sync.Mutex
	token   string
	port    int
	server  *http.Server
	running bool
	lastErr string
}

func newDesktopBridge(s *desktopServer) *desktopBridge {
	port := defaultBridgePort
	if v := strings.TrimSpace(os.Getenv("APM_BRIDGE_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	return &desktopBridge{s: s, port: port}
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

func (b *desktopBridge) loadToken() {
	file := bridgeTokenFile()
	if file != "" {
		if data, err := os.ReadFile(file); err == nil {
			if t := strings.TrimSpace(string(data)); t != "" {
				b.token = t
				return
			}
		}
	}
	b.token = newBridgeToken()
	if file != "" {
		_ = os.WriteFile(file, []byte(b.token), 0600)
	}
}

func (b *desktopBridge) start() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.loadToken()
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(b.port))
	if err != nil {
		b.running = false
		b.lastErr = err.Error()
		return
	}
	b.server = &http.Server{Handler: http.HandlerFunc(b.handle), ReadHeaderTimeout: 10 * time.Second}
	b.running = true
	go func() {
		_ = b.server.Serve(ln)
		b.mu.Lock()
		b.running = false
		b.mu.Unlock()
	}()
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
	res := map[string]any{"token": b.token, "port": b.port, "running": b.running}
	if b.lastErr != "" && !b.running {
		res["error"] = b.lastErr
	}
	return res
}

func (b *desktopBridge) rotate() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.token = newBridgeToken()
	if file := bridgeTokenFile(); file != "" {
		return os.WriteFile(file, []byte(b.token), 0600)
	}
	return nil
}

func (b *desktopBridge) currentToken() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.token
}

func bridgeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func entryNameOf(f map[string]any) string {
	for _, k := range []string{"account", "name", "label", "ssid", "alias", "service", "product_name", "username"} {
		if s := toStr(f[k]); s != "" {
			return s
		}
	}
	return ""
}

func (b *desktopBridge) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "content-type, x-apm-token")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			bridgeJSON(w, 500, map[string]any{"ok": false, "error": fmt.Sprint(rec)})
		}
	}()
	s := b.s
	if r.URL.Path == "/api/info" {
		s.mu.Lock()
		unlocked := s.unlocked()
		s.mu.Unlock()
		bridgeJSON(w, 200, map[string]any{"ok": true, "name": "APM", "version": Version, "unlocked": unlocked})
		return
	}
	if r.Header.Get("x-apm-token") == "" || r.Header.Get("x-apm-token") != b.currentToken() {
		bridgeJSON(w, 401, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}
	var body map[string]json.RawMessage
	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			bridgeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				bridgeJSON(w, 500, map[string]any{"ok": false, "error": "Invalid JSON body"})
				return
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.unlocked() {
		bridgeJSON(w, 423, map[string]any{"ok": false, "error": "locked"})
		return
	}
	switch {
	case r.URL.Path == "/api/entries" && r.Method == http.MethodGet:
		bridgeJSON(w, 200, map[string]any{"ok": true, "entries": s.bridgeEntries()})
	case r.URL.Path == "/api/credentials" && r.Method == http.MethodGet:
		bridgeJSON(w, 200, map[string]any{"ok": true, "credentials": s.bridgeCredentials(r.URL.Query().Get("rpId"))})
	case r.URL.Path == "/api/passkeys" && r.Method == http.MethodGet:
		bridgeJSON(w, 200, map[string]any{"ok": true, "passkeys": s.bridgePasskeys()})
	case r.URL.Path == "/api/passkeys" && r.Method == http.MethodPost:
		code, res := s.bridgeSavePasskey(body)
		bridgeJSON(w, code, res)
	case r.URL.Path == "/api/passkeys/remove" && r.Method == http.MethodPost:
		code, res := s.bridgeRemovePasskey(body)
		bridgeJSON(w, code, res)
	case r.URL.Path == "/api/passkeys/rename" && r.Method == http.MethodPost:
		code, res := s.bridgeRenamePasskey(body)
		bridgeJSON(w, code, res)
	case r.URL.Path == "/api/passkeys/use" && r.Method == http.MethodPost:
		code, res := s.bridgeUsePasskey(body)
		bridgeJSON(w, code, res)
	default:
		bridgeJSON(w, 404, map[string]any{"ok": false, "error": "not found"})
	}
}

func (s *desktopServer) bridgeEntries() []map[string]any {
	out := []map[string]any{}
	for _, t := range bridgeEntryTypes {
		spec, ok := src.ItemTypeByJSONKey(t.vaultKey)
		if !ok {
			continue
		}
		for _, ref := range s.vault.ItemRefs() {
			if ref.Spec.ID != spec.ID {
				continue
			}
			f := s.vault.ItemRecordFields(ref)
			name := entryNameOf(f)
			if name == "" {
				name = fmt.Sprintf("%s %d", t.label, ref.Index+1)
			}
			sub := ""
			for _, k := range []string{"username", "account", "email"} {
				if v := toStr(f[k]); v != "" {
					sub = v
					break
				}
			}
			out = append(out, map[string]any{
				"vaultKey":    t.vaultKey,
				"index":       ref.Index,
				"type":        t.label,
				"icon":        "",
				"name":        name,
				"sub":         sub,
				"space":       ref.Space,
				"hasPasskeys": len(s.vault.ItemPasskeys(ref)) > 0,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(toStr(out[i]["name"])) < strings.ToLower(toStr(out[j]["name"]))
	})
	return out
}

func (s *desktopServer) bridgeCredentials(rpID string) []map[string]any {
	out := []map[string]any{}
	for _, e := range s.vault.Entries {
		for _, pk := range e.Passkeys {
			if pk.CredentialID == "" {
				continue
			}
			if rpID != "" && pk.RPID != "" && pk.RPID != rpID {
				continue
			}
			user := pk.UserName
			if user == "" {
				user = e.Account
			}
			var priv any = nil
			if len(pk.PrivateKey) > 0 {
				priv = pk.PrivateKey
			}
			out = append(out, map[string]any{
				"credentialId": pk.CredentialID,
				"rpId":         pk.RPID,
				"userName":     user,
				"userHandle":   pk.UserHandle,
				"signCount":    pk.SignCount,
				"privateKey":   priv,
			})
		}
	}
	return out
}

func jsTimeOrNil(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

func (s *desktopServer) bridgePasskeys() []map[string]any {
	out := []map[string]any{}
	for i, e := range s.vault.Entries {
		for _, pk := range e.Passkeys {
			if pk.CredentialID == "" {
				continue
			}
			created := pk.CreatedAt
			name := e.Account
			if name == "" {
				name = fmt.Sprintf("Password %d", i+1)
			}
			out = append(out, map[string]any{
				"credentialId":    pk.CredentialID,
				"rpId":            pk.RPID,
				"userName":        pk.UserName,
				"userDisplayName": pk.UserDisplayName,
				"label":           pk.Label,
				"createdAt":       jsTimeOrNil(&created),
				"lastUsedAt":      jsTimeOrNil(pk.LastUsedAt),
				"signCount":       pk.SignCount,
				"ref":             map[string]any{"vaultKey": "entries", "index": i},
				"entryName":       name,
				"entryType":       "Password",
				"entryIcon":       "",
				"space":           e.Space,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := toStr(out[i]["rpId"]), toStr(out[j]["rpId"])
		if a != b {
			return a < b
		}
		return toStr(out[i]["entryName"]) < toStr(out[j]["entryName"])
	})
	return out
}

func uuidV4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func jsNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func (s *desktopServer) bridgeWrite(note, action, details string) (int, map[string]any) {
	if err := s.save(note); err != nil {
		return 500, map[string]any{"ok": false, "error": err.Error()}
	}
	if action != "" {
		src.LogAction(action, details)
	}
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
	return 0, nil
}

func (s *desktopServer) bridgeSavePasskey(body map[string]json.RawMessage) (int, map[string]any) {
	if s.isReadonly() {
		return 423, map[string]any{"ok": false, "error": "readonly"}
	}
	var in struct {
		RPID            string          `json:"rpId"`
		UserName        string          `json:"userName"`
		UserDisplayName string          `json:"userDisplayName"`
		UserHandle      string          `json:"userHandle"`
		CredentialID    string          `json:"credentialId"`
		PrivateKey      json.RawMessage `json:"privateKey"`
		SignCount       int64           `json:"signCount"`
	}
	if raw, ok := body["passkey"]; ok {
		_ = json.Unmarshal(raw, &in)
	}
	if in.CredentialID == "" || len(in.PrivateKey) == 0 || string(in.PrivateKey) == "null" {
		return 500, map[string]any{"ok": false, "error": "Malformed passkey payload"}
	}
	pk := src.Passkey{
		ID:              uuidV4(),
		RPID:            in.RPID,
		UserName:        in.UserName,
		UserDisplayName: in.UserDisplayName,
		UserHandle:      in.UserHandle,
		CredentialID:    in.CredentialID,
		PrivateKey:      in.PrivateKey,
		SignCount:       in.SignCount,
		CreatedAt:       jsNow(),
	}
	var ref struct {
		VaultKey string `json:"vaultKey"`
		Index    *int   `json:"index"`
	}
	var newEntry struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Space    string `json:"space"`
	}
	if raw, ok := body["ref"]; ok {
		_ = json.Unmarshal(raw, &ref)
	}
	if raw, ok := body["newEntry"]; ok {
		_ = json.Unmarshal(raw, &newEntry)
	}
	entryName := ""
	switch {
	case ref.VaultKey != "":
		if ref.VaultKey != "entries" {
			return 500, map[string]any{"ok": false, "error": "Passkeys can only be saved to logins"}
		}
		if ref.Index == nil || *ref.Index < 0 || *ref.Index >= len(s.vault.Entries) {
			return 500, map[string]any{"ok": false, "error": "Entry not found"}
		}
		e := &s.vault.Entries[*ref.Index]
		e.Passkeys = append(e.Passkeys, pk)
		entryName = e.Account
	case strings.TrimSpace(newEntry.Name) != "":
		name := strings.TrimSpace(newEntry.Name)
		space := normalizeSpaceParam(newEntry.Space)
		space = s.ensureSpace(space)
		found := false
		for i := range s.vault.Entries {
			if strings.EqualFold(s.vault.Entries[i].Account, name) && strings.EqualFold(s.vault.Entries[i].Space, space) {
				s.vault.Entries[i].Passkeys = append(s.vault.Entries[i].Passkeys, pk)
				found = true
				break
			}
		}
		if !found {
			refNew, err := s.vault.AddItem("password", space, map[string]any{"account": name, "username": newEntry.Username, "password": "", "website": in.RPID})
			if err != nil {
				return 500, map[string]any{"ok": false, "error": err.Error()}
			}
			s.vault.Entries[refNew.Index].Passkeys = []src.Passkey{pk}
		}
		entryName = name
	default:
		return 500, map[string]any{"ok": false, "error": "No target entry"}
	}
	if code, res := s.bridgeWrite("Saved a passkey to "+entryName, "PASSKEY_SAVED", fmt.Sprintf("rpId=%s entry=%s", in.RPID, entryName)); code != 0 {
		return code, res
	}
	return 200, map[string]any{"ok": true, "entryName": entryName}
}

func bodyString(body map[string]json.RawMessage, key string) string {
	var v string
	if raw, ok := body[key]; ok {
		_ = json.Unmarshal(raw, &v)
	}
	return v
}

func (s *desktopServer) bridgeRemovePasskey(body map[string]json.RawMessage) (int, map[string]any) {
	if s.isReadonly() {
		return 423, map[string]any{"ok": false, "error": "readonly"}
	}
	cid := bodyString(body, "credentialId")
	i, j, ok := s.vault.PasskeyOwner(cid)
	if !ok || cid == "" {
		return 200, map[string]any{"ok": true, "removed": false, "entryName": ""}
	}
	e := &s.vault.Entries[i]
	e.Passkeys = append(e.Passkeys[:j], e.Passkeys[j+1:]...)
	if e.Passkeys == nil {
		e.Passkeys = []src.Passkey{}
	}
	if code, res := s.bridgeWrite("Removed a passkey from "+e.Account, "PASSKEY_DELETED", fmt.Sprintf("credential=%s entry=%s", cid, e.Account)); code != 0 {
		return code, res
	}
	return 200, map[string]any{"ok": true, "removed": true, "entryName": e.Account}
}

func (s *desktopServer) bridgeRenamePasskey(body map[string]json.RawMessage) (int, map[string]any) {
	if s.isReadonly() {
		return 423, map[string]any{"ok": false, "error": "readonly"}
	}
	cid := bodyString(body, "credentialId")
	i, j, ok := s.vault.PasskeyOwner(cid)
	if !ok || cid == "" {
		return 200, map[string]any{"ok": true, "renamed": false, "entryName": ""}
	}
	label := strings.TrimSpace(bodyString(body, "label"))
	if r := []rune(label); len(r) > 120 {
		label = string(r[:120])
	}
	e := &s.vault.Entries[i]
	if label == "" {
		return 200, map[string]any{"ok": true, "renamed": false, "entryName": e.Account}
	}
	e.Passkeys[j].Label = label
	if code, res := s.bridgeWrite("Renamed a passkey on "+e.Account, "PASSKEY_RENAMED", fmt.Sprintf("credential=%s entry=%s", cid, e.Account)); code != 0 {
		return code, res
	}
	return 200, map[string]any{"ok": true, "renamed": true, "entryName": e.Account}
}

func (s *desktopServer) bridgeUsePasskey(body map[string]json.RawMessage) (int, map[string]any) {
	cid := bodyString(body, "credentialId")
	if cid == "" {
		return 200, map[string]any{"ok": true, "changed": false}
	}
	var sign int64
	if raw, ok := body["signCount"]; ok {
		var f float64
		if json.Unmarshal(raw, &f) == nil {
			sign = int64(f)
		}
	}
	now := jsNow()
	changed := false
	for i := range s.vault.Entries {
		for j := range s.vault.Entries[i].Passkeys {
			pk := &s.vault.Entries[i].Passkeys[j]
			if pk.CredentialID != cid {
				continue
			}
			if sign > pk.SignCount {
				pk.SignCount = sign
				changed = true
			}
			n := now
			pk.LastUsedAt = &n
			changed = true
		}
	}
	if !changed {
		return 200, map[string]any{"ok": true, "changed": false}
	}
	if !s.isReadonly() {
		if err := s.saveQuiet(); err != nil {
			return 500, map[string]any{"ok": false, "error": err.Error()}
		}
	}
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
	return 200, map[string]any{"ok": true, "changed": true}
}
