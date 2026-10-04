package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	src "github.com/aaravmaloo/apm/src"
	"github.com/pquerna/otp/totp"
	"golang.org/x/net/publicsuffix"
)

var bridgeTypeLabels = map[string]string{
	"password":    "Login",
	"totp":        "Authenticator",
	"note":        "Secure note",
	"wifi":        "Wi-Fi network",
	"govid":       "Government ID",
	"medical":     "Medical record",
	"travel":      "Travel",
	"contact":     "Contact",
	"recovery":    "Recovery codes",
	"apikey":      "API key",
	"token":       "Token",
	"ssh_key":     "SSH key",
	"ssh_config":  "SSH host",
	"cloud":       "Cloud credentials",
	"k8s":         "Kubernetes",
	"docker":      "Docker registry",
	"cicd":        "CI/CD secret",
	"certificate": "Certificate",
	"banking":     "Card or account",
	"license":     "Software license",
	"legal":       "Legal contract",
	"document":    "Document",
	"photo":       "Photo",
	"audio":       "Audio",
	"video":       "Video",
}

var bridgeSecretKeys = map[string][]string{
	"password":    {"password"},
	"totp":        {"secret"},
	"wifi":        {"password"},
	"govid":       {"id_number"},
	"travel":      {"booking_code"},
	"recovery":    {"codes", "used"},
	"apikey":      {"key"},
	"token":       {"token"},
	"ssh_key":     {"private_key"},
	"ssh_config":  {"private_key"},
	"cloud":       {"access_key", "secret_key"},
	"docker":      {"token"},
	"cicd":        {"webhook", "env_vars"},
	"certificate": {"cert_data", "private_key"},
	"banking":     {"details", "cvv"},
	"license":     {"serial_key"},
	"document":    {"password"},
	"note":        {"content"},
	"medical":     {"insurance_id"},
}

const guiWordCount = 355

var guiCommonPasswords = []string{"password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "sunset", "football", "baseball", "master", "shadow", "login", "abc123", "passw0rd", "trustno1"}

var (
	guiPassphraseRe = regexp.MustCompile(`^[A-Za-z]+(-[A-Za-z]+[0-9]?)+$`)
	guiYearRe       = regexp.MustCompile(`(19|20)\d\d`)
	guiNameDigitsRe = regexp.MustCompile(`^[A-Z][a-z]+\d+[!@#$%]?$`)
	guiDigitsRe     = regexp.MustCompile(`^\d+$`)
	guiEd25519Re    = regexp.MustCompile(`(?i)ed25519|AAAAC3`)
	guiLowerRe      = regexp.MustCompile(`[a-z]`)
	guiUpperRe      = regexp.MustCompile(`[A-Z]`)
	guiDigitRe      = regexp.MustCompile(`[0-9]`)
	guiSymbolRe     = regexp.MustCompile(`[^A-Za-z0-9]`)
)

func jsLength(s string) int {
	return len(utf16.Encode([]rune(s)))
}

func jsRound(x float64) float64 {
	return math.Floor(x + 0.5)
}

func jsSlice(s string, start, end int) string {
	u := utf16.Encode([]rune(s))
	if end > len(u) {
		end = len(u)
	}
	if start > end {
		return ""
	}
	return string(utf16.Decode(u[start:end]))
}

func jsTail(s string, n int) string {
	u := utf16.Encode([]rune(s))
	if len(u) <= n {
		return s
	}
	return string(utf16.Decode(u[len(u)-n:]))
}

func guiTripleRun(s string) bool {
	u := utf16.Encode([]rune(s))
	for i := 0; i+2 < len(u); i++ {
		c := u[i]
		if c == '\n' || c == '\r' || c == 0x2028 || c == 0x2029 {
			continue
		}
		if u[i+1] == c && u[i+2] == c {
			return true
		}
	}
	return false
}

func guiEntropy(pw string) int {
	if pw == "" {
		return 0
	}
	if guiPassphraseRe.MatchString(pw) && len(strings.Split(pw, "-")) >= 3 {
		n := float64(len(strings.Split(pw, "-")))
		extra := 0.0
		if guiDigitRe.MatchString(pw) {
			extra = 3.3
		}
		return int(jsRound(n*math.Log2(guiWordCount) + extra))
	}
	pool := 0
	if guiLowerRe.MatchString(pw) {
		pool += 26
	}
	if guiUpperRe.MatchString(pw) {
		pool += 26
	}
	if guiDigitRe.MatchString(pw) {
		pool += 10
	}
	if guiSymbolRe.MatchString(pw) {
		pool += 24
	}
	length := float64(jsLength(pw))
	bits := length * math.Log2(math.Max(float64(pool), 1))
	low := strings.ToLower(pw)
	for _, c := range guiCommonPasswords {
		if strings.Contains(low, c) {
			bits *= 0.35
			break
		}
	}
	if guiTripleRun(pw) {
		bits *= 0.8
	}
	if guiYearRe.MatchString(pw) {
		bits -= 6
	}
	if guiNameDigitsRe.MatchString(pw) {
		bits *= 0.55
	}
	if guiDigitsRe.MatchString(pw) {
		bits = math.Min(bits, length*3.32)
	}
	return int(math.Max(0, jsRound(bits)))
}

func guiScore(bits int) int {
	switch {
	case bits < 28:
		return 0
	case bits < 40:
		return 1
	case bits < 60:
		return 2
	case bits < 80:
		return 3
	}
	return 4
}

func guiFmtBytes(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1048576:
		return strconv.FormatInt((n+512)/1024, 10) + " KB"
	}
	tenths := (n*10 + 524288) / 1048576
	return strconv.FormatInt(tenths/10, 10) + "." + strconv.FormatInt(tenths%10, 10) + " MB"
}

func joinNonEmpty(sep string, parts ...string) string {
	out := []string{}
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if p != "" {
			return p
		}
	}
	return ""
}

func bridgeList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, toStr(e))
		}
		return out
	}
	return nil
}

func bridgeValueString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []string:
		return strings.Join(t, "\n")
	case []any:
		return strings.Join(bridgeList(t), "\n")
	}
	return toStr(v)
}

func bridgeSub(typeID string, f map[string]any) string {
	g := func(k string) string { return toStr(f[k]) }
	switch typeID {
	case "password":
		return firstNonEmpty(g("username"), g("website"))
	case "totp":
		return "6 digits · 30s"
	case "wifi":
		return joinNonEmpty(" · ", g("ssid"), g("security_type"))
	case "govid":
		exp := ""
		if e := g("expiry"); e != "" {
			exp = "expires " + jsSlice(e, 0, 4)
		}
		return joinNonEmpty(" · ", g("type"), exp)
	case "travel":
		return firstNonEmpty(g("ticket_number"), g("loyalty_program"))
	case "contact":
		return firstNonEmpty(g("email"), g("phone"))
	case "recovery":
		codes := len(bridgeList(f["codes"]))
		used := len(bridgeList(f["used"]))
		return fmt.Sprintf("%d codes · %d unused", codes, codes-used)
	case "apikey":
		return g("service")
	case "token":
		return g("type")
	case "ssh_key":
		k := g("private_key")
		if guiEd25519Re.MatchString(k) {
			return "ed25519"
		}
		if strings.Contains(k, "RSA") {
			return "RSA"
		}
		return "Private key"
	case "ssh_config":
		out := joinNonEmpty("@", g("user"), g("host"))
		if p := g("port"); p != "" && p != "22" {
			out += ":" + p
		}
		return out
	case "cloud":
		return firstNonEmpty(g("region"), g("account_id"))
	case "k8s":
		return joinNonEmpty(" · ", g("namespace"), g("cluster_url"))
	case "docker":
		if u := g("username"); u != "" {
			return u + " · " + g("registry_url")
		}
		return g("registry_url")
	case "cicd":
		n := 0
		for _, part := range strings.FieldsFunc(g("env_vars"), func(r rune) bool { return r == '\n' || r == ',' }) {
			if strings.Contains(part, "=") {
				n++
			}
		}
		if n > 0 {
			return fmt.Sprintf("%d variables", n)
		}
		return "Webhook"
	case "certificate":
		exp := ""
		if e := g("expiry"); e != "" {
			exp = "expires " + e
		}
		return joinNonEmpty(" · ", g("issuer"), exp)
	case "banking":
		d := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, g("details"))
		kind := g("type")
		if kind == "" {
			kind = "Card"
		}
		if jsLength(d) >= 8 {
			return kind + " ···· " + jsTail(d, 4)
		}
		return kind
	case "license":
		return g("activation_info")
	case "legal":
		return g("parties_involved")
	case "document", "photo", "audio", "video":
		file, ok := f["file"].(map[string]any)
		if !ok {
			return ""
		}
		var size int64
		switch n := file["size"].(type) {
		case int:
			size = int64(n)
		case int64:
			size = n
		case float64:
			size = int64(n)
		}
		return toStr(file["name"]) + " · " + guiFmtBytes(size)
	}
	return ""
}

func bridgeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(h, ".")
	return strings.TrimPrefix(h, "www.")
}

func registrableDomain(host string) string {
	if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

func totpDomainsFor(v *src.Vault, account string) []string {
	out := []string{}
	for d, acc := range v.TOTPDomainLinks {
		if acc == account && d != "" {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

type bridgeIndex struct {
	v          *src.Vault
	refs       []src.VaultItemRef
	fields     map[string]map[string]any
	totps      []src.VaultItemRef
	byPassword map[string][]src.VaultItemRef
}

func newBridgeIndex(v *src.Vault) *bridgeIndex {
	ix := &bridgeIndex{v: v, refs: v.ItemRefs(), fields: map[string]map[string]any{}, byPassword: map[string][]src.VaultItemRef{}}
	for _, r := range ix.refs {
		f := v.ItemRecordFields(r)
		ix.fields[r.ID] = f
		switch r.Spec.ID {
		case "totp":
			ix.totps = append(ix.totps, r)
		case "password", "wifi":
			if pw := toStr(f["password"]); pw != "" {
				ix.byPassword[pw] = append(ix.byPassword[pw], r)
			}
			if r.Spec.ID == "password" && toStr(f["totp"]) != "" {
				ix.totps = append(ix.totps, r)
			}
		}
	}
	return ix
}

func (ix *bridgeIndex) find(id string) (src.VaultItemRef, bool) {
	for _, r := range ix.refs {
		if r.ID == id {
			return r, true
		}
	}
	return src.VaultItemRef{}, false
}

func (ix *bridgeIndex) linkedTOTP(login src.VaultItemRef) (src.VaultItemRef, bool) {
	if login.Spec.ID != "password" {
		return src.VaultItemRef{}, false
	}
	if toStr(ix.fields[login.ID]["totp"]) != "" {
		return login, true
	}
	host := bridgeHost(toStr(ix.fields[login.ID]["website"]))
	reg := registrableDomain(host)
	domains := map[string][]string{}
	for _, t := range ix.totps {
		domains[t.ID] = totpDomainsFor(ix.v, t.Title)
	}
	tiers := []func(t src.VaultItemRef) bool{
		func(t src.VaultItemRef) bool {
			for _, d := range domains[t.ID] {
				if host != "" && bridgeHost(d) == host {
					return true
				}
			}
			return false
		},
		func(t src.VaultItemRef) bool {
			for _, d := range domains[t.ID] {
				if reg != "" && registrableDomain(bridgeHost(d)) == reg {
					return true
				}
			}
			return false
		},
		func(t src.VaultItemRef) bool {
			return strings.TrimSpace(login.Title) != "" && strings.EqualFold(strings.TrimSpace(t.Title), strings.TrimSpace(login.Title))
		},
	}
	for _, match := range tiers {
		for _, same := range []bool{true, false} {
			for _, t := range ix.totps {
				if t.Spec.ID != "totp" || strings.EqualFold(t.Space, login.Space) != same {
					continue
				}
				if match(t) {
					return t, true
				}
			}
		}
	}
	return src.VaultItemRef{}, false
}

func bridgeTitle(ref src.VaultItemRef) string {
	if strings.TrimSpace(ref.Title) != "" {
		return ref.Title
	}
	if l, ok := bridgeTypeLabels[ref.Spec.ID]; ok {
		return l
	}
	return ref.Spec.ID
}

func (ix *bridgeIndex) health(ref src.VaultItemRef) any {
	if ref.Spec.ID != "password" && ref.Spec.ID != "wifi" {
		return nil
	}
	pw := toStr(ix.fields[ref.ID]["password"])
	if pw == "" {
		return nil
	}
	bits := guiEntropy(pw)
	score := guiScore(bits)
	reused := []string{}
	for _, o := range ix.byPassword[pw] {
		if o.ID != ref.ID {
			reused = append(reused, bridgeTitle(o))
		}
	}
	return map[string]any{"weak": jsLength(pw) < 8 || score <= 1, "reused": reused, "bits": bits, "score": score}
}

func appendUniqueURL(list []string, vals ...string) []string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		dup := false
		for _, x := range list {
			if strings.EqualFold(x, v) {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, v)
		}
	}
	return list
}

func (s *desktopServer) bridgeSummary(ix *bridgeIndex, ref src.VaultItemRef) map[string]any {
	f := ix.fields[ref.ID]
	tel := s.vault.ItemTelemetry(ref)
	urls := []string{}
	username := ""
	totpID := ""
	switch ref.Spec.ID {
	case "password":
		urls = appendUniqueURL(urls, toStr(f["website"]))
		urls = appendUniqueURL(urls, bridgeList(f["urls"])...)
		username = toStr(f["username"])
		if t, ok := ix.linkedTOTP(ref); ok {
			totpID = t.ID
		}
	case "totp":
		urls = appendUniqueURL(urls, totpDomainsFor(s.vault, ref.Title)...)
	case "docker":
		username = toStr(f["username"])
	}
	hasSecret := false
	if ref.Spec.Secret != "" {
		hasSecret = bridgeValueString(f[ref.Spec.Secret]) != ""
	}
	return map[string]any{
		"id":        ref.ID,
		"type":      ref.Spec.ID,
		"title":     bridgeTitle(ref),
		"sub":       bridgeSub(ref.Spec.ID, f),
		"space":     ref.Space,
		"fav":       s.isFavorite(ref.ID),
		"urls":      urls,
		"username":  username,
		"totpId":    totpID,
		"hasSecret": hasSecret,
		"passkeys":  len(s.vault.ItemPasskeys(ref)),
		"created":   ms(tel.CreatedAt),
		"modified":  ms(tel.UpdatedAt),
		"used":      ms(tel.LastAccessed),
		"health":    ix.health(ref),
	}
}

func (s *desktopServer) bridgeDetail(ix *bridgeIndex, ref src.VaultItemRef) map[string]any {
	out := s.bridgeSummary(ix, ref)
	f := map[string]any{}
	for k, v := range ix.fields[ref.ID] {
		f[k] = v
	}
	secrets := map[string]any{}
	for _, k := range bridgeSecretKeys[ref.Spec.ID] {
		val, ok := f[k]
		if !ok {
			continue
		}
		if n := jsLength(bridgeValueString(val)); n > 0 {
			secrets[k] = n
		}
		f[k] = ""
	}
	list := []map[string]any{}
	for _, p := range s.vault.ItemPasskeys(ref) {
		created := p.CreatedAt
		list = append(list, map[string]any{
			"credentialId": p.CredentialID,
			"rpId":         p.RPID,
			"userName":     p.UserName,
			"label":        p.Label,
			"createdAt":    parseJSTime(&created),
			"lastUsedAt":   parseJSTime(p.LastUsedAt),
			"signCount":    p.SignCount,
		})
	}
	versions := 0
	if d := s.vault.Desktop; d != nil && d.Versions != nil {
		versions = len(d.Versions[ref.ID])
	}
	out["f"] = f
	out["secrets"] = secrets
	out["passkeyList"] = list
	out["versions"] = versions
	return out
}

func (s *desktopServer) bridgeRecordAccess(ref src.VaultItemRef) error {
	s.vault.RecordItemAccess(ref)
	if s.isReadonly() {
		return nil
	}
	if err := s.saveQuiet(); err != nil {
		return err
	}
	s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
	return nil
}

func (s *desktopServer) bridgeSpaces() []map[string]any {
	out := []map[string]any{}
	for _, sp := range s.spacesView() {
		out = append(out, map[string]any{"id": sp["id"], "name": sp["name"]})
	}
	return out
}

func bridgeItemsList(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	ix := newBridgeIndex(s.vault)
	items := make([]map[string]any, 0, len(ix.refs))
	for _, r := range ix.refs {
		items = append(items, s.bridgeSummary(ix, r))
	}
	return map[string]any{"items": items, "spaces": s.bridgeSpaces()}, nil
}

func bridgeItemGet(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	ix := newBridgeIndex(s.vault)
	ref, ok := ix.find(c.params["id"])
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	return map[string]any{"item": s.bridgeDetail(ix, ref)}, nil
}

func bridgeItemReveal(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		Key string `json:"key"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	ref, ok := s.vault.FindItem(c.params["id"])
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	f := s.vault.ItemRecordFields(ref)
	key := strings.TrimSpace(in.Key)
	val, has := f[key]
	if key == "" || key == "file" || !has {
		return nil, rpcErr("invalid", "This item has no field called "+strconv.Quote(key)+".")
	}
	if err := s.bridgeRecordAccess(ref); err != nil {
		return nil, err
	}
	return map[string]any{"value": bridgeValueString(val)}, nil
}

func bridgeTOTPSecret(v *src.Vault, ref src.VaultItemRef) string {
	key := "secret"
	if ref.Spec.ID == "password" {
		key = "totp"
	}
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(toStr(v.ItemRecordFields(ref)[key])), " ", ""))
}

func bridgeTOTPCode(secret string, step int64) string {
	code, err := totp.GenerateCode(secret, time.Unix(step*30, 0))
	if err != nil {
		return ""
	}
	return code
}

func (s *desktopServer) bridgeTOTPView(ix *bridgeIndex, ref src.VaultItemRef, nowMs int64) map[string]any {
	step := nowMs / 1000 / 30
	secret := bridgeTOTPSecret(s.vault, ref)
	domain := toStr(ix.fields[ref.ID]["domain"])
	if ref.Spec.ID == "password" {
		domain = bridgeHost(toStr(ix.fields[ref.ID]["website"]))
	}
	return map[string]any{
		"id":     ref.ID,
		"title":  bridgeTitle(ref),
		"sub":    bridgeSub("totp", ix.fields[ref.ID]),
		"space":  ref.Space,
		"domain": domain,
		"code":   bridgeTOTPCode(secret, step),
		"next":   bridgeTOTPCode(secret, step+1),
		"period": 30,
		"step":   step,
	}
}

func bridgeFill(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		ID string `json:"id"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	ix := newBridgeIndex(s.vault)
	ref, ok := ix.find(in.ID)
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	if ref.Spec.ID != "password" {
		return nil, rpcErr("not_login", "Only logins can be filled into a page.")
	}
	f := ix.fields[ref.ID]
	var code any
	if t, ok := ix.linkedTOTP(ref); ok {
		now := time.Now()
		otp := bridgeTOTPCode(bridgeTOTPSecret(s.vault, t), now.Unix()/30)
		if otp != "" {
			code = map[string]any{"code": otp, "remaining": 30 - int(now.Unix()%30)}
		}
	}
	if err := s.bridgeRecordAccess(ref); err != nil {
		return nil, err
	}
	return map[string]any{"id": ref.ID, "username": toStr(f["username"]), "password": toStr(f["password"]), "totp": code}, nil
}

func bridgeTOTPList(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	ix := newBridgeIndex(s.vault)
	now := time.Now().UnixMilli()
	codes := []map[string]any{}
	for _, t := range ix.totps {
		codes = append(codes, s.bridgeTOTPView(ix, t, now))
	}
	return map[string]any{"now": now, "codes": codes}, nil
}

func bridgeTOTPOne(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	ix := newBridgeIndex(s.vault)
	ref, ok := ix.find(c.params["id"])
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	switch ref.Spec.ID {
	case "totp":
	case "password":
		t, ok := ix.linkedTOTP(ref)
		if !ok {
			return nil, rpcErr("not_found", "No authenticator is linked to this login.")
		}
		ref = t
	default:
		return nil, rpcErr("not_found", "This item has no one-time code.")
	}
	now := time.Now().UnixMilli()
	return map[string]any{"now": now, "code": s.bridgeTOTPView(ix, ref, now)}, nil
}

func (s *desktopServer) bridgeSummaryByID(id string) map[string]any {
	ix := newBridgeIndex(s.vault)
	ref, ok := ix.find(id)
	if !ok {
		return nil
	}
	return s.bridgeSummary(ix, ref)
}

func bridgeItemAdd(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	res, err := hItemAdd(s, c.body)
	if err != nil {
		return nil, err
	}
	s.emitChanged(res)
	id := ""
	if m, ok := res.(map[string]any); ok {
		if item, ok := m["item"].(map[string]any); ok {
			id = toStr(item["id"])
		}
	}
	return map[string]any{"item": s.bridgeSummaryByID(id)}, nil
}

func bridgeItemUpdate(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		F     map[string]any `json:"f"`
		Space *string        `json:"space"`
		Note  string         `json:"note"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	params := map[string]any{"id": c.params["id"], "f": in.F, "note": in.Note}
	if in.Space != nil {
		params["space"] = *in.Space
	}
	raw, _ := json.Marshal(params)
	res, err := hItemUpdate(s, raw)
	if err != nil {
		return nil, err
	}
	s.emitChanged(res)
	id := c.params["id"]
	if m, ok := res.(map[string]any); ok {
		if v := toStr(m["id"]); v != "" {
			id = v
		}
	}
	return map[string]any{"id": id, "item": s.bridgeSummaryByID(id)}, nil
}

func bridgeItemTrash(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	raw, _ := json.Marshal(map[string]any{"ids": []string{c.params["id"]}})
	res, err := hItemDelete(s, raw)
	if err != nil {
		return nil, err
	}
	s.emitChanged(res)
	return map[string]any{}, nil
}

func bridgeItemFavorite(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	s := b.s
	var in struct {
		On bool `json:"on"`
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	id := c.params["id"]
	if _, ok := s.vault.FindItem(id); !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	raw, _ := json.Marshal(map[string]any{"ids": []string{id}, "on": in.On})
	res, err := hItemFavorite(s, raw)
	if err != nil {
		return nil, err
	}
	s.emitChanged(res)
	return map[string]any{"item": s.bridgeSummaryByID(id)}, nil
}
