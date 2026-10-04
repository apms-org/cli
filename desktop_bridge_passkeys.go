package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	src "github.com/aaravmaloo/apm/src"
	"golang.org/x/net/publicsuffix"
)

type passkeyJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64urlDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.DecodeString(s)
}

func normalizeCredentialID(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	return strings.NewReplacer("+", "-", "/", "_").Replace(s)
}

func findPasskey(v *src.Vault, credentialID string) (int, int, bool) {
	want := normalizeCredentialID(credentialID)
	if want == "" {
		return 0, 0, false
	}
	for i := range v.Entries {
		for j := range v.Entries[i].Passkeys {
			if normalizeCredentialID(v.Entries[i].Passkeys[j].CredentialID) == want {
				return i, j, true
			}
		}
	}
	return 0, 0, false
}

func cborHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= 0xff:
		return []byte{m | 24, byte(n)}
	case n <= 0xffff:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		out := []byte{m | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(out[1:], uint32(n))
		return out
	}
	out := []byte{m | 27, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(out[1:], n)
	return out
}

func cborInt(v int64) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte {
	return append(cborHead(2, uint64(len(b))), b...)
}

func cborText(s string) []byte {
	return append(cborHead(3, uint64(len(s))), s...)
}

func coseES256Key(x, y []byte) []byte {
	out := cborHead(5, 5)
	out = append(out, cborInt(1)...)
	out = append(out, cborInt(2)...)
	out = append(out, cborInt(3)...)
	out = append(out, cborInt(-7)...)
	out = append(out, cborInt(-1)...)
	out = append(out, cborInt(1)...)
	out = append(out, cborInt(-2)...)
	out = append(out, cborBytes(x)...)
	out = append(out, cborInt(-3)...)
	out = append(out, cborBytes(y)...)
	return out
}

func noneAttestationObject(authData []byte) []byte {
	out := cborHead(5, 3)
	out = append(out, cborText("fmt")...)
	out = append(out, cborText("none")...)
	out = append(out, cborText("attStmt")...)
	out = append(out, cborHead(5, 0)...)
	out = append(out, cborText("authData")...)
	out = append(out, cborBytes(authData)...)
	return out
}

func passkeyAuthData(rpID string, flags byte, signCount uint32, attested []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37+len(attested))
	out = append(out, rpHash[:]...)
	out = append(out, flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	out = append(out, sc[:]...)
	return append(out, attested...)
}

func passkeyPrivateKey(raw json.RawMessage) (*ecdsa.PrivateKey, error) {
	var jwk passkeyJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		var wrapped string
		if json.Unmarshal(raw, &wrapped) != nil || json.Unmarshal([]byte(wrapped), &jwk) != nil {
			return nil, errors.New("the stored key is not a JWK")
		}
	}
	if jwk.Kty != "" && jwk.Kty != "EC" {
		return nil, errors.New("the stored key is not an EC key")
	}
	if jwk.Crv != "" && jwk.Crv != "P-256" {
		return nil, errors.New("the stored key is not on P-256")
	}
	d, err := b64urlDecode(jwk.D)
	if err != nil || len(d) < 24 || len(d) > 32 {
		return nil, errors.New("the stored key has no usable private scalar")
	}
	if len(d) < 32 {
		d = append(make([]byte, 32-len(d)), d...)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, err
	}
	if jwk.X != "" && jwk.Y != "" {
		pub, err := priv.PublicKey.Bytes()
		if err != nil {
			return nil, err
		}
		x, xerr := b64urlDecode(jwk.X)
		y, yerr := b64urlDecode(jwk.Y)
		if xerr != nil || yerr != nil || !bytes.Equal(pub[1:33], leftPad32(x)) || !bytes.Equal(pub[33:65], leftPad32(y)) {
			return nil, errors.New("the stored public key does not match the private key")
		}
	}
	return priv, nil
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

func bridgeRPCheck(origin, rpID string) error {
	fail := rpErr(origin, rpID)
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fail
	}
	host := strings.ToLower(u.Hostname())
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" {
			return fail
		}
	default:
		return fail
	}
	rp := strings.ToLower(strings.TrimSpace(rpID))
	if rp == "" || host == "" {
		return fail
	}
	if net.ParseIP(host) != nil {
		if rp != host {
			return fail
		}
		return nil
	}
	if rp != host && !strings.HasSuffix(host, "."+rp) {
		return fail
	}
	if rp == "localhost" {
		return nil
	}
	if !strings.Contains(rp, ".") {
		return fail
	}
	if ps, _ := publicsuffix.PublicSuffix(rp); ps == rp {
		return fail
	}
	return nil
}

func rpErr(origin, rpID string) error {
	return rpcErr("rp_mismatch", fmt.Sprintf("The site %s cannot use passkeys for %s.", strings.TrimSpace(origin), strings.TrimSpace(rpID)))
}

func (s *desktopServer) passwordRefIDs() map[int]string {
	out := map[int]string{}
	for _, r := range s.vault.ItemRefs() {
		if r.Spec.ID == "password" {
			out[r.Index] = r.ID
		}
	}
	return out
}

func entryDisplayName(e src.Entry, i int) string {
	if e.Account != "" {
		return e.Account
	}
	return fmt.Sprintf("Password %d", i+1)
}

func bridgePasskeyList(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	q := c.r.URL.Query()
	rp := strings.ToLower(strings.TrimSpace(q.Get("rpId")))
	if rp != "" {
		if err := bridgeRPCheck(q.Get("origin"), rp); err != nil {
			return nil, err
		}
	}
	ids := s.passwordRefIDs()
	out := []map[string]any{}
	for i, e := range s.vault.Entries {
		for _, pk := range e.Passkeys {
			if pk.CredentialID == "" {
				continue
			}
			if rp != "" && !strings.EqualFold(pk.RPID, rp) {
				continue
			}
			created := pk.CreatedAt
			out = append(out, map[string]any{
				"credentialId":    pk.CredentialID,
				"rpId":            pk.RPID,
				"userName":        pk.UserName,
				"userDisplayName": pk.UserDisplayName,
				"label":           pk.Label,
				"createdAt":       parseJSTime(&created),
				"lastUsedAt":      parseJSTime(pk.LastUsedAt),
				"signCount":       pk.SignCount,
				"entryId":         ids[i],
				"entryName":       entryDisplayName(e, i),
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
	return map[string]any{"passkeys": out}, nil
}

func bridgePasskeyRemove(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		CredentialID string `json:"credentialId"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	i, j, ok := findPasskey(s.vault, in.CredentialID)
	if !ok {
		return map[string]any{"removed": false, "entryName": ""}, nil
	}
	e := &s.vault.Entries[i]
	e.Passkeys = append(e.Passkeys[:j], e.Passkeys[j+1:]...)
	if e.Passkeys == nil {
		e.Passkeys = []src.Passkey{}
	}
	if err := s.save("Removed a passkey from " + e.Account); err != nil {
		return nil, err
	}
	src.LogAction("PASSKEY_DELETED", fmt.Sprintf("credential=%s entry=%s", in.CredentialID, e.Account))
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
	return map[string]any{"removed": true, "entryName": e.Account}, nil
}

func bridgePasskeyRename(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		CredentialID string `json:"credentialId"`
		Label        string `json:"label"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	i, j, ok := findPasskey(s.vault, in.CredentialID)
	if !ok {
		return map[string]any{"renamed": false, "entryName": ""}, nil
	}
	label := strings.TrimSpace(in.Label)
	if r := []rune(label); len(r) > 120 {
		label = string(r[:120])
	}
	e := &s.vault.Entries[i]
	if label == "" {
		return map[string]any{"renamed": false, "entryName": e.Account}, nil
	}
	e.Passkeys[j].Label = label
	if err := s.save("Renamed a passkey on " + e.Account); err != nil {
		return nil, err
	}
	src.LogAction("PASSKEY_RENAMED", fmt.Sprintf("credential=%s entry=%s", in.CredentialID, e.Account))
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
	return map[string]any{"renamed": true, "entryName": e.Account}, nil
}

type passkeyCreateInput struct {
	Origin string `json:"origin"`
	RPID   string `json:"rpId"`
	RPName string `json:"rpName"`
	User   struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	ClientDataHash     string   `json:"clientDataHash"`
	UV                 bool     `json:"uv"`
	ExcludeCredentials []string `json:"excludeCredentials"`
	Target             struct {
		ID       string `json:"id"`
		NewEntry *struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			Space    string `json:"space"`
		} `json:"newEntry"`
	} `json:"target"`
}

func bridgePasskeyCreate(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in passkeyCreateInput
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	rp := strings.ToLower(strings.TrimSpace(in.RPID))
	if err := bridgeRPCheck(in.Origin, rp); err != nil {
		return nil, err
	}
	if cdh, err := b64urlDecode(in.ClientDataHash); err != nil || len(cdh) != 32 {
		return nil, rpcErr("invalid", "clientDataHash must be 32 bytes, base64url encoded.")
	}
	userHandle, err := b64urlDecode(in.User.ID)
	if err != nil || len(userHandle) == 0 || len(userHandle) > 64 {
		return nil, rpcErr("invalid", "user.id must be 1 to 64 bytes, base64url encoded.")
	}
	for _, id := range in.ExcludeCredentials {
		if _, _, ok := findPasskey(s.vault, id); ok {
			return nil, rpcErr("exists", "APM already has a passkey for this account on "+rp+".")
		}
	}
	var target src.VaultItemRef
	newName, newUser, newSpace := "", "", ""
	switch {
	case strings.TrimSpace(in.Target.ID) != "":
		ref, ok := s.vault.FindItem(strings.TrimSpace(in.Target.ID))
		if !ok {
			return nil, rpcErr("not_found", "That login no longer exists.")
		}
		if ref.Spec.ID != "password" {
			return nil, rpcErr("not_login", "Passkeys can only be saved to logins.")
		}
		target = ref
	case in.Target.NewEntry != nil && strings.TrimSpace(in.Target.NewEntry.Name) != "":
		newName = strings.TrimSpace(in.Target.NewEntry.Name)
		newUser = strings.TrimSpace(in.Target.NewEntry.Username)
		newSpace = normalizeSpaceParam(in.Target.NewEntry.Space)
	default:
		return nil, rpcErr("invalid", "Choose a login to save the passkey to, or name a new one.")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	d, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	x, y := pub[1:33], pub[33:65]
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, err
	}
	jwk, err := json.Marshal(passkeyJWK{Kty: "EC", Crv: "P-256", X: b64url(x), Y: b64url(y), D: b64url(d)})
	if err != nil {
		return nil, err
	}
	flags := byte(0x41)
	if in.UV {
		flags |= 0x04
	}
	attested := make([]byte, 0, 16+2+len(credID)+77)
	attested = append(attested, make([]byte, 16)...)
	attested = append(attested, byte(len(credID)>>8), byte(len(credID)))
	attested = append(attested, credID...)
	attested = append(attested, coseES256Key(x, y)...)
	authData := passkeyAuthData(rp, flags, 0, attested)
	userName := strings.TrimSpace(in.User.Name)
	display := strings.TrimSpace(in.User.DisplayName)
	if display == "" {
		display = userName
	}
	pk := src.Passkey{
		ID:              uuidV4(),
		RPID:            rp,
		UserName:        userName,
		UserDisplayName: display,
		UserHandle:      b64url(userHandle),
		CredentialID:    b64url(credID),
		PrivateKey:      jwk,
		SignCount:       0,
		CreatedAt:       jsNow(),
	}
	if newName != "" {
		space := s.ensureSpace(newSpace)
		found := false
		for _, r := range s.vault.ItemRefs() {
			if r.Spec.ID == "password" && strings.EqualFold(strings.TrimSpace(r.Title), newName) && strings.EqualFold(r.Space, space) {
				target = r
				found = true
				break
			}
		}
		if !found {
			ref, err := s.vault.AddItem("password", space, map[string]any{"account": newName, "username": newUser, "password": "", "website": rp})
			if err != nil {
				return nil, err
			}
			target = ref
		}
	}
	e := &s.vault.Entries[target.Index]
	e.Passkeys = append(e.Passkeys, pk)
	entryName := e.Account
	if err := s.save("Saved a passkey to " + entryName); err != nil {
		return nil, err
	}
	src.LogAction("PASSKEY_SAVED", fmt.Sprintf("rpId=%s entry=%s", rp, entryName))
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
	return map[string]any{
		"credentialId":       pk.CredentialID,
		"authenticatorData":  b64url(authData),
		"attestationObject":  b64url(noneAttestationObject(authData)),
		"publicKey":          b64url(spki),
		"publicKeyAlgorithm": -7,
		"entryId":            target.ID,
		"entryName":          entryName,
	}, nil
}

func bridgePasskeyAssert(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		Origin         string `json:"origin"`
		RPID           string `json:"rpId"`
		CredentialID   string `json:"credentialId"`
		ClientDataHash string `json:"clientDataHash"`
		UV             bool   `json:"uv"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	rp := strings.ToLower(strings.TrimSpace(in.RPID))
	if err := bridgeRPCheck(in.Origin, rp); err != nil {
		return nil, err
	}
	i, j, ok := findPasskey(s.vault, in.CredentialID)
	if !ok {
		return nil, rpcErr("not_found", "That passkey is not in this vault.")
	}
	pk := &s.vault.Entries[i].Passkeys[j]
	if !strings.EqualFold(strings.TrimSpace(pk.RPID), rp) {
		return nil, rpcErr("rp_mismatch", "This passkey belongs to "+pk.RPID+", not "+rp+".")
	}
	cdh, err := b64urlDecode(in.ClientDataHash)
	if err != nil || len(cdh) != 32 {
		return nil, rpcErr("invalid", "clientDataHash must be 32 bytes, base64url encoded.")
	}
	priv, err := passkeyPrivateKey(pk.PrivateKey)
	if err != nil {
		return nil, rpcErr("internal", "This passkey's private key cannot be read: "+err.Error()+".")
	}
	// A counter of 0 means "no counter", as synced passkeys report it. Keeping
	// it there lets the passkey move to other managers with Credential
	// Exchange, which only accepts passkeys whose counter was never used.
	count := pk.SignCount
	if count > 0 {
		count++
	}
	if count < 0 {
		count = 0
	}
	if count > 0xffffffff {
		count = 0xffffffff
	}
	flags := byte(0x01)
	if in.UV {
		flags |= 0x04
	}
	authData := passkeyAuthData(rp, flags, uint32(count), nil)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdh...))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	now := jsNow()
	pk.SignCount = count
	pk.LastUsedAt = &now
	if !s.isReadonly() {
		if err := s.saveQuiet(); err != nil {
			return nil, err
		}
	}
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
	e := s.vault.Entries[i]
	userName := pk.UserName
	if userName == "" {
		userName = e.Username
	}
	return map[string]any{
		"credentialId":      pk.CredentialID,
		"authenticatorData": b64url(authData),
		"signature":         b64url(sig),
		"userHandle":        normalizeCredentialID(pk.UserHandle),
		"userName":          userName,
		"entryId":           s.passwordRefIDs()[i],
	}, nil
}
