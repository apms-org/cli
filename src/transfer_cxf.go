package apm

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// FIDO Alliance Credential Exchange Format (CXF) v1.0. The format is the data
// model the Credential Exchange Protocol moves between providers; APM reads
// and writes it as a plain JSON file. A file may hold the full Header or a
// single Account, which is what OS-mediated exchanges hand over.

const (
	cxfExporterRpID = "apm.local"
	cxfExtensionAPM = cxfExporterRpID + "/item"
)

func init() {
	RegisterTransferFormat(TransferFormat{
		ID: "cxf", Label: "Credential Exchange (CXF)", Vendor: "cxf", Ext: []string{".json", ".cxf"},
		Help:   "A FIDO Credential Exchange Format file (JSON). It carries logins, passkeys with their private keys, one-time codes, cards, notes, SSH keys and Wi-Fi networks from any provider that supports credential exchange.",
		Detect: detectCXF, Parse: parseCXF,
	})
	RegisterTransferExporter(TransferExporter{
		ID: "cxf", Label: "Credential Exchange (CXF)", Vendor: "cxf", Ext: "json", Passkeys: true, Secrets: true,
		Help: "The FIDO Alliance standard for moving credentials between password managers. Passkeys come along with their private keys, but CXF only allows passkeys that were never used to sign in (sign count 0). Use the APM or Bitwarden format to keep used passkeys. The file is not encrypted.",
		SkipPasskey: func(p Passkey) string {
			if CXFPasskeyExcluded(p) {
				return "Credential Exchange only allows passkeys that never counted a sign-in. Use the APM or Bitwarden format for these"
			}
			return ""
		},
		Write: writeCXF,
	})
}

// CXFPasskeyExcluded reports whether CXF export must leave a passkey out.
// CXF 1.0, 3.3.12: "Passkeys using a non-zero signature counter MUST be
// excluded from the export".
func CXFPasskeyExcluded(p Passkey) bool { return p.SignCount != 0 }

// Editable fields

type cxfField struct {
	ID        string `json:"id,omitempty"`
	FieldType string `json:"fieldType"`
	Value     string `json:"value"`
	Label     string `json:"label,omitempty"`
}

func (f *cxfField) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] != '{' {
		var s any
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		f.FieldType, f.Value = "string", cxfScalar(s)
		return nil
	}
	var raw struct {
		ID        string `json:"id"`
		FieldType string `json:"fieldType"`
		Value     any    `json:"value"`
		Label     string `json:"label"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	f.ID, f.FieldType, f.Label, f.Value = raw.ID, raw.FieldType, raw.Label, cxfScalar(raw.Value)
	return nil
}

func cxfScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func cxfString(v string) *cxfField { return cxfTyped("string", v) }

func cxfSecret(v string) *cxfField { return cxfTyped("concealed-string", v) }

func cxfTyped(t, v string) *cxfField {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &cxfField{FieldType: t, Value: v}
}

type cxfCred map[string]json.RawMessage

func (c cxfCred) str(key string) string {
	var s any
	if raw, ok := c[key]; ok && json.Unmarshal(raw, &s) == nil {
		if _, isMap := s.(map[string]any); !isMap {
			return cxfScalar(s)
		}
	}
	return c.field(key)
}

func (c cxfCred) field(key string) string {
	raw, ok := c[key]
	if !ok {
		return ""
	}
	var f cxfField
	if json.Unmarshal(raw, &f) != nil {
		return ""
	}
	return f.Value
}

func (c cxfCred) num(key string) int {
	n, _ := strconv.Atoi(c.str(key))
	return n
}

// Document shapes

type cxfHeader struct {
	Version             cxfVersion   `json:"version"`
	ExporterRpID        string       `json:"exporterRpId"`
	ExporterDisplayName string       `json:"exporterDisplayName"`
	Timestamp           int64        `json:"timestamp"`
	Accounts            []cxfAccount `json:"accounts"`
}

type cxfVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

type cxfAccount struct {
	ID          string          `json:"id"`
	Username    string          `json:"username"`
	Email       string          `json:"email"`
	FullName    string          `json:"fullName,omitempty"`
	Collections []cxfCollection `json:"collections"`
	Items       []cxfItem       `json:"items"`
}

type cxfCollection struct {
	ID             string          `json:"id"`
	CreationAt     int64           `json:"creationAt,omitempty"`
	ModifiedAt     int64           `json:"modifiedAt,omitempty"`
	Title          string          `json:"title"`
	Items          []cxfLinkedItem `json:"items"`
	SubCollections []cxfCollection `json:"subCollections,omitempty"`
}

type cxfLinkedItem struct {
	Item    string `json:"item"`
	Account string `json:"account,omitempty"`
}

type cxfScope struct {
	URLs        []string          `json:"urls"`
	AndroidApps []json.RawMessage `json:"androidApps"`
}

type cxfItem struct {
	ID         string            `json:"id"`
	CreationAt int64             `json:"creationAt,omitempty"`
	ModifiedAt int64             `json:"modifiedAt,omitempty"`
	Title      string            `json:"title"`
	Subtitle   string            `json:"subtitle,omitempty"`
	Favorite   bool              `json:"favorite,omitempty"`
	Scope      *cxfScope         `json:"scope,omitempty"`
	Creds      []json.RawMessage `json:"credentials"`
	Tags       []string          `json:"tags,omitempty"`
	Extensions []json.RawMessage `json:"extensions,omitempty"`
}

type cxfAPMExtension struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Space  *string        `json:"space,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Import

func detectCXF(name string, data []byte) int {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 || trim[0] != '{' {
		return 0
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(trim, &probe) != nil {
		return 0
	}
	if _, ok := probe["exporterRpId"]; ok {
		return 100
	}
	hasCreds := func(raw json.RawMessage) bool {
		var items []map[string]json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return false
		}
		for _, it := range items {
			if _, ok := it["credentials"]; ok {
				return true
			}
		}
		return false
	}
	if raw, ok := probe["accounts"]; ok {
		var accts []map[string]json.RawMessage
		if json.Unmarshal(raw, &accts) == nil {
			for _, a := range accts {
				if hasCreds(a["items"]) {
					return 95
				}
			}
		}
	}
	if raw, ok := probe["items"]; ok && hasCreds(raw) {
		return 92
	}
	return 0
}

func parseCXF(name string, data []byte, password string) (*TransferSet, error) {
	trim := bytes.TrimSpace(data)
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(trim, &probe); err != nil {
		return nil, transferErr(TransferInvalid, "This Credential Exchange file is not valid JSON.")
	}
	var head cxfHeader
	if _, ok := probe["accounts"]; ok {
		if err := json.Unmarshal(trim, &head); err != nil {
			return nil, transferErr(TransferInvalid, "This Credential Exchange file could not be read: %v", err)
		}
	} else {
		var acct cxfAccount
		if err := json.Unmarshal(trim, &acct); err != nil {
			return nil, transferErr(TransferInvalid, "This Credential Exchange file could not be read: %v", err)
		}
		head.Accounts = []cxfAccount{acct}
	}
	set := &TransferSet{Format: "cxf", FormatLabel: "Credential Exchange (CXF)", Vendor: "cxf"}
	if d := strings.TrimSpace(head.ExporterDisplayName); d != "" {
		set.FormatLabel = "Credential Exchange (CXF) from " + d
	}
	if head.Version.Major > 1 {
		set.Warn("This file uses CXF version %d.%d. APM reads version 1, so some data may be missing.", head.Version.Major, head.Version.Minor)
	}
	p := &cxfParser{set: set, unknown: map[string]bool{}}
	multi := len(head.Accounts) > 1
	for _, a := range head.Accounts {
		folders := map[string]string{}
		var walk func(list []cxfCollection, prefix string)
		walk = func(list []cxfCollection, prefix string) {
			for _, c := range list {
				title := strings.TrimSpace(c.Title)
				if prefix != "" {
					title = prefix + "/" + title
				}
				for _, li := range c.Items {
					if _, seen := folders[li.Item]; !seen {
						folders[li.Item] = title
					}
				}
				walk(c.SubCollections, title)
			}
		}
		walk(a.Collections, "")
		fallback := ""
		if multi {
			fallback = firstNonEmpty(a.FullName, a.Username, a.Email)
		}
		for _, x := range a.Items {
			folder := folders[x.ID]
			if folder == "" {
				folder = fallback
			}
			p.item(x, folder)
		}
	}
	unknown := make([]string, 0, len(p.unknown))
	for t := range p.unknown {
		unknown = append(unknown, t)
	}
	sort.Strings(unknown)
	for _, t := range unknown {
		set.Warn("Credentials of type %q are not supported and were left out.", t)
	}
	return set, nil
}

type cxfParser struct {
	set     *TransferSet
	unknown map[string]bool
}

type cxfNote struct{ label, value string }

func (p *cxfParser) item(x cxfItem, folder string) {
	set := p.set
	title := strings.TrimSpace(x.Title)
	var ext *cxfAPMExtension
	for _, raw := range x.Extensions {
		var e cxfAPMExtension
		if json.Unmarshal(raw, &e) == nil && e.Name == cxfExtensionAPM && e.Type != "" {
			ext = &e
		}
	}
	creds := []cxfCred{}
	for _, raw := range x.Creds {
		var c cxfCred
		if json.Unmarshal(raw, &c) != nil {
			continue
		}
		creds = append(creds, c)
	}
	typeOf := func(c cxfCred) string {
		var t string
		_ = json.Unmarshal(c["type"], &t)
		return t
	}
	urls := []string{}
	if x.Scope != nil {
		for _, u := range x.Scope.URLs {
			if u = strings.TrimSpace(u); u != "" {
				urls = append(urls, u)
			}
		}
	}
	primary := -1
	notes := []cxfNote{}
	var warns []string
	add := func(it TransferItem) int {
		it.Folder = folder
		if ext != nil && ext.Space != nil {
			it.Space, it.HasSpace = *ext.Space, true
		}
		if primary >= 0 {
			it.Link = primary
		} else {
			it.Favorite = x.Favorite
		}
		idx := set.Add(it)
		if primary < 0 {
			primary = idx
		}
		return idx
	}

	var basics, passkeys, totps []cxfCred
	for _, c := range creds {
		switch typeOf(c) {
		case "basic-auth":
			basics = append(basics, c)
		case "passkey":
			passkeys = append(passkeys, c)
		case "totp":
			totps = append(totps, c)
		}
	}

	login := -1
	if len(basics) > 0 || len(passkeys) > 0 {
		it := NewTransferItem("password", title)
		if len(basics) > 0 {
			it.Set("username", basics[0].str("username"))
			it.Set("password", basics[0].str("password"))
			for _, b := range basics[1:] {
				it.Note("Another login", strings.TrimSpace(b.str("username")+" "+b.str("password")))
			}
		}
		if len(urls) > 0 {
			it.Set("website", urls[0])
			if len(urls) > 1 {
				it.Set("urls", urls[1:])
			}
		}
		extWarned := false
		for _, c := range passkeys {
			key, err := DecodeFlexibleBase64(c.str("key"))
			rp := c.str("rpId")
			user := c.str("username")
			if it.Get("username") == "" {
				it.Set("username", user)
			}
			if it.Get("website") == "" && rp != "" {
				it.Set("website", "https://"+rp)
			}
			if err != nil || len(key) == 0 {
				it.DropPasskey(rp, user, "The export does not include its private key")
				continue
			}
			jwk, err := PasskeyKeyFromPKCS8(key)
			if err != nil {
				msg := err.Error()
				it.DropPasskey(rp, user, strings.ToUpper(msg[:1])+msg[1:])
				continue
			}
			it.AddPasskey(ImportedPasskey{RPID: rp, UserName: user, UserDisplayName: c.str("userDisplayName"), UserHandle: c.str("userHandle"), CredentialID: c.str("credentialId"), Key: jwk, Created: cxfTime(x.CreationAt)})
			if !extWarned && len(c["fido2Extensions"]) > 0 && string(c["fido2Extensions"]) != "null" && string(c["fido2Extensions"]) != "{}" {
				extWarned = true
				it.Warn("Passkey extension data (such as hmac-secret or large blobs) is not kept")
			}
		}
		login = add(it)
	}
	for _, c := range totps {
		uri := cxfOTPAuth(c, title)
		if login >= 0 {
			set.AddTOTP(login, uri)
			continue
		}
		it := NewTransferItem("totp", title)
		secret, problem := TOTPSecretFrom(uri)
		it.Set("secret", secret)
		if problem != "" {
			it.Problem("%s", problem)
		}
		if len(urls) > 0 {
			it.Set("domain", normalizeDomain(urls[0]))
		}
		add(it)
	}

	if ext != nil && ext.Type != "password" && ext.Type != "totp" && len(ext.Fields) > 0 {
		if _, ok := ItemTypeByID(ext.Type); ok {
			it := NewTransferItem(ext.Type, title)
			for k, v := range ext.Fields {
				it.Fields[k] = v
			}
			add(it)
			for _, c := range creds {
				if t := typeOf(c); t == "file" {
					warns = append(warns, "Attached files are not part of a Credential Exchange file")
				}
			}
			p.finishNotes(primary, title, folder, x, notes, warns, ext)
			return
		}
	}

	contact := -1
	for _, c := range creds {
		t := typeOf(c)
		switch t {
		case "basic-auth", "passkey", "totp":
		case "note":
			notes = append(notes, cxfNote{"", c.str("content")})
		case "generated-password":
			notes = append(notes, cxfNote{"Generated password", c.str("password")})
		case "custom-fields":
			var fields []cxfField
			_ = json.Unmarshal(c["fields"], &fields)
			group := c.str("label")
			for _, f := range fields {
				label := f.Label
				if label == "" {
					label = group
				}
				notes = append(notes, cxfNote{label, f.Value})
			}
		case "credit-card":
			it := NewTransferItem("banking", title)
			it.Set("type", "Card")
			it.Set("details", c.str("number"))
			it.Set("cvv", c.str("verificationNumber"))
			it.Set("expiry", cxfCardExpiry(c.str("expiryDate")))
			it.Note("Cardholder", c.str("fullName"))
			it.Note("Card type", c.str("cardType"))
			it.Note("PIN", c.str("pin"))
			it.Note("Valid from", c.str("validFrom"))
			add(it)
		case "ssh-key":
			it := NewTransferItem("ssh_key", title)
			key, err := cxfSSHPrivateKey(c.str("privateKey"), c.str("keyComment"))
			if err != nil {
				it.Problem("The SSH key could not be read: %v", err)
			}
			it.Set("private_key", key)
			it.Note("Comment", c.str("keyComment"))
			it.Note("Created", c.str("creationDate"))
			it.Note("Expires", c.str("expiryDate"))
			it.Note("Generated by", c.str("keyGenerationSource"))
			add(it)
		case "wifi":
			it := NewTransferItem("wifi", firstNonEmpty(c.str("ssid"), title))
			it.Set("password", c.str("passphrase"))
			it.Set("security_type", cxfWifiToAPM(c.str("networkSecurityType")))
			if c.str("hidden") == "true" {
				it.Note("Hidden network", "Yes")
			}
			add(it)
		case "api-key":
			it := NewTransferItem("apikey", title)
			it.Set("key", c.str("key"))
			service := c.str("url")
			if h := normalizeDomain(service); h != "" {
				service = h
			}
			it.Set("service", firstNonEmpty(service, c.str("keyType")))
			it.Note("Username", c.str("username"))
			it.Note("Key type", c.str("keyType"))
			it.Note("URL", c.str("url"))
			it.Note("Valid from", c.str("validFrom"))
			it.Note("Expires", c.str("expiryDate"))
			add(it)
		case "passport", "drivers-license", "identity-document":
			kind := map[string]string{"passport": "Passport", "drivers-license": "Driver's License", "identity-document": "National ID"}[t]
			it := NewTransferItem("govid", title)
			it.Set("type", kind)
			it.Set("id_number", firstNonEmpty(c.str("passportNumber"), c.str("licenseNumber"), c.str("documentNumber"), c.str("identificationNumber")))
			it.Set("expiry", c.str("expiryDate"))
			for _, k := range []string{"fullName", "issuingCountry", "country", "territory", "nationality", "birthDate", "birthPlace", "sex", "issueDate", "issuingAuthority", "passportType", "nationalIdentificationNumber", "licenseClass", "identificationNumber"} {
				if k == "identificationNumber" && it.Get("id_number") == c.str(k) {
					continue
				}
				it.Note(cxfLabel(k), c.str(k))
			}
			add(it)
		case "address", "person-name":
			if contact < 0 {
				contact = add(NewTransferItem("contact", title))
			}
			ci := &set.Items[contact]
			if t == "address" {
				parts := []string{}
				for _, k := range []string{"streetAddress", "city", "territory", "postalCode", "country"} {
					if v := c.str(k); v != "" {
						parts = append(parts, v)
					}
				}
				ci.Set("address", joinNotes(ci.Get("address"), strings.Join(parts, "\n")))
				ci.Set("phone", c.str("tel"))
			} else {
				parts := []string{}
				for _, k := range []string{"title", "given", "given2", "surnamePrefix", "surname", "surname2", "generation", "credentials"} {
					if v := c.str(k); v != "" {
						parts = append(parts, v)
					}
				}
				ci.Note("Full name", strings.Join(parts, " "))
				ci.Note("Nickname", c.str("givenInformal"))
			}
		case "file":
			warns = append(warns, "Attached files are not part of a Credential Exchange file")
		case "item-reference":
		default:
			if t != "" {
				p.unknown[t] = true
			}
		}
	}
	p.finishNotes(primary, title, folder, x, notes, warns, ext)
}

func (p *cxfParser) finishNotes(primary int, title, folder string, x cxfItem, notes []cxfNote, warns []string, ext *cxfAPMExtension) {
	set := p.set
	if len(x.Tags) > 0 {
		notes = append(notes, cxfNote{"Tags", strings.Join(x.Tags, ", ")})
	}
	if primary < 0 {
		has := false
		for _, n := range notes {
			if strings.TrimSpace(n.value) != "" {
				has = true
			}
		}
		if !has && len(warns) == 0 {
			if len(x.Creds) == 0 {
				return
			}
			it := NewTransferItem("note", title)
			it.Folder = folder
			it.Problem("It holds no credential APM can import")
			set.Add(it)
			return
		}
		it := NewTransferItem("note", title)
		it.Folder, it.Favorite = folder, x.Favorite
		if ext != nil && ext.Space != nil {
			it.Space, it.HasSpace = *ext.Space, true
		}
		content := []string{}
		for _, n := range notes {
			if n.label == "" {
				content = append(content, n.value)
			} else if n.value != "" {
				content = append(content, n.label+": "+n.value)
			}
		}
		it.Set("content", strings.Join(content, "\n"))
		primary = set.Add(it)
		notes = nil
	}
	it := &set.Items[primary]
	for _, n := range notes {
		it.Note(n.label, n.value)
	}
	seen := map[string]bool{}
	for _, w := range warns {
		if !seen[w] {
			seen[w] = true
			it.Warn("%s", w)
		}
	}
}

func cxfTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func cxfOTPAuth(c cxfCred, title string) string {
	q := url.Values{}
	q.Set("secret", c.str("secret"))
	if d := c.num("digits"); d != 0 {
		q.Set("digits", strconv.Itoa(d))
	}
	if p := c.num("period"); p != 0 {
		q.Set("period", strconv.Itoa(p))
	}
	if a := c.str("algorithm"); a != "" {
		q.Set("algorithm", strings.ToUpper(a))
	}
	issuer := firstNonEmpty(c.str("issuer"), title)
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	label := issuer
	if u := c.str("username"); u != "" {
		label += ":" + u
	}
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode()
}

func cxfCardExpiry(ym string) string {
	ym = strings.TrimSpace(ym)
	if len(ym) >= 7 && ym[4] == '-' {
		return ym[5:7] + "/" + ym[2:4]
	}
	return ym
}

func cxfWifiToAPM(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "wpa3-personal":
		return "WPA3 Personal"
	case "wpa2-personal", "wpa-personal":
		return "WPA2 Personal"
	case "wpa2-enterprise":
		return "WPA2 Enterprise"
	case "wep":
		return "WEP"
	case "unsecured":
		return "Open"
	}
	return t
}

func apmWifiToCXF(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "wpa3 personal":
		return "wpa3-personal"
	case "wpa2 personal":
		return "wpa2-personal"
	case "wpa2 enterprise":
		return "wpa2-enterprise"
	case "wep":
		return "wep"
	case "open":
		return "unsecured"
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(t), " ", "-"))
}

func cxfLabel(key string) string {
	var b strings.Builder
	for i, r := range key {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte(' ')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	s := b.String()
	return strings.ToUpper(s[:1]) + s[1:]
}

func cxfSSHPrivateKey(b64 string, comment string) (string, error) {
	der, err := DecodeFlexibleBase64(b64)
	if err != nil || len(der) == 0 {
		return "", fmt.Errorf("the private key is missing")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", fmt.Errorf("the private key is not PKCS#8")
	}
	if block, err := ssh.MarshalPrivateKey(key, comment); err == nil {
		return string(pem.EncodeToMemory(block)), nil
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// Export

func cxfID(parts ...string) string {
	sum := sha256.Sum256([]byte("apm-cxf\x00" + strings.Join(parts, "\x00")))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func cxfCredential(kind string, fields map[string]any) map[string]any {
	out := map[string]any{"type": kind}
	for k, v := range fields {
		switch t := v.(type) {
		case nil:
			continue
		case *cxfField:
			if t == nil {
				continue
			}
		case string:
			if t == "" {
				continue
			}
		}
		out[k] = v
	}
	return out
}

func cxfURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" || strings.Contains(u, "://") {
		return u
	}
	return "https://" + u
}

func writeCXF(items []TransferItem, opt ExportOptions) ([]byte, error) {
	created := opt.Created
	if created.IsZero() {
		created = time.Now()
	}
	byName := map[string]int{}
	byHost := map[string][]int{}
	for i, it := range items {
		if it.Type != "password" {
			continue
		}
		byName[spaceKey(it.Space)+"\x00"+strings.ToLower(it.Title)] = i
		if h := normalizeDomain(it.Get("website")); h != "" {
			byHost[spaceKey(it.Space)+"\x00"+h] = append(byHost[spaceKey(it.Space)+"\x00"+h], i)
		}
	}
	attached := map[int][]int{}
	consumed := map[int]bool{}
	for i, it := range items {
		if it.Type != "totp" {
			continue
		}
		target := -1
		if j, ok := byName[spaceKey(it.Space)+"\x00"+strings.ToLower(it.Title)]; ok {
			target = j
		} else if h := normalizeDomain(it.Get("domain")); h != "" {
			if list := byHost[spaceKey(it.Space)+"\x00"+h]; len(list) == 1 {
				target = list[0]
			}
		}
		if target >= 0 {
			attached[target] = append(attached[target], i)
			consumed[i] = true
		}
	}
	totpCred := func(it TransferItem, user string) map[string]any {
		return cxfCredential("totp", map[string]any{"secret": it.Get("secret"), "period": 30, "digits": 6, "algorithm": "sha1", "issuer": it.Title, "username": user})
	}

	acct := cxfAccount{ID: cxfID("account", opt.VaultName), FullName: opt.VaultName, Collections: []cxfCollection{}}
	out := []map[string]any{}
	spaces := map[string]*cxfCollection{}
	spaceOrder := []string{}
	for i, it := range items {
		if consumed[i] {
			continue
		}
		id := cxfID(it.Type, spaceKey(it.Space), strings.ToLower(it.Title))
		creds := []map[string]any{}
		ext := map[string]any{"name": cxfExtensionAPM, "type": it.Type, "space": it.Space}
		urls := []string{}
		switch it.Type {
		case "password":
			user := it.Get("username")
			if user != "" || it.Get("password") != "" {
				creds = append(creds, cxfCredential("basic-auth", map[string]any{"username": cxfString(user), "password": cxfSecret(it.Get("password"))}))
			}
			for _, pk := range it.Passkeys {
				if CXFPasskeyExcluded(pk) {
					continue
				}
				der, err := PasskeyPKCS8(pk)
				if err != nil {
					continue
				}
				cred, _ := CredentialIDBytes(pk.CredentialID)
				handle, _ := DecodeFlexibleBase64(pk.UserHandle)
				creds = append(creds, map[string]any{"type": "passkey", "credentialId": base64.RawURLEncoding.EncodeToString(cred), "rpId": pk.RPID,
					"username": pk.UserName, "userDisplayName": firstNonEmpty(pk.UserDisplayName, pk.UserName), "userHandle": base64.RawURLEncoding.EncodeToString(handle),
					"key": base64.RawURLEncoding.EncodeToString(der)})
			}
			for _, j := range attached[i] {
				creds = append(creds, totpCred(items[j], user))
			}
			if n := it.Get("notes"); n != "" {
				creds = append(creds, cxfCredential("note", map[string]any{"content": cxfString(n)}))
			}
			if w := it.Get("website"); w != "" {
				urls = append(urls, cxfURL(w))
			}
			for _, u := range toStringList(it.Fields["urls"]) {
				urls = append(urls, cxfURL(u))
			}
		case "totp":
			creds = append(creds, totpCred(it, ""))
			if d := it.Get("domain"); d != "" {
				urls = append(urls, cxfURL(d))
			}
		case "note":
			creds = append(creds, cxfCredential("note", map[string]any{"content": cxfString(it.Get("content"))}))
		case "banking":
			if strings.EqualFold(it.Get("type"), "card") || it.Get("type") == "" {
				creds = append(creds, cxfCredential("credit-card", map[string]any{"number": cxfSecret(it.Get("details")), "verificationNumber": cxfSecret(it.Get("cvv")), "expiryDate": cxfTyped("year-month", apmCardExpiryToCXF(it.Get("expiry")))}))
			} else {
				creds = append(creds, cxfCustomFields(it))
			}
		case "ssh_key":
			if c, ok := cxfSSHCredential(it.Get("private_key"), it.Title); ok {
				creds = append(creds, c)
			} else {
				creds = append(creds, cxfCustomFields(it))
			}
		case "wifi":
			creds = append(creds, cxfCredential("wifi", map[string]any{"ssid": cxfString(it.Title), "networkSecurityType": cxfTyped("wifi-network-security-type", apmWifiToCXF(it.Get("security_type"))), "passphrase": cxfSecret(it.Get("password"))}))
			if r := it.Get("router_ip"); r != "" {
				creds = append(creds, cxfCredential("custom-fields", map[string]any{"fields": []*cxfField{{FieldType: "string", Label: "Router address", Value: r}}}))
			}
		case "apikey":
			creds = append(creds, cxfCredential("api-key", map[string]any{"key": cxfSecret(it.Get("key"))}))
			if s := it.Get("service"); s != "" {
				creds = append(creds, cxfCredential("custom-fields", map[string]any{"fields": []*cxfField{{FieldType: "string", Label: "Service", Value: s}}}))
			}
		case "token":
			creds = append(creds, cxfCredential("api-key", map[string]any{"key": cxfSecret(it.Get("token")), "keyType": cxfString(it.Get("type"))}))
		case "govid":
			kind, num := "identity-document", "documentNumber"
			switch strings.ToLower(it.Get("type")) {
			case "passport":
				kind, num = "passport", "passportNumber"
			case "driver's license", "drivers license":
				kind, num = "drivers-license", "licenseNumber"
			}
			creds = append(creds, cxfCredential(kind, map[string]any{num: cxfString(it.Get("id_number")), "expiryDate": cxfTyped("date", it.Get("expiry"))}))
		case "contact":
			creds = append(creds, cxfCredential("address", map[string]any{"streetAddress": cxfString(it.Get("address")), "tel": cxfString(it.Get("phone"))}))
			creds = append(creds, cxfCustomFields(it, "address", "phone"))
		default:
			creds = append(creds, cxfCustomFields(it))
		}
		if it.Type != "password" && it.Type != "totp" {
			f := map[string]any{}
			for k, v := range it.Fields {
				if !isEmptyValue(v) {
					f[k] = v
				}
			}
			ext["fields"] = f
		}
		entry := map[string]any{"id": id, "title": it.Title, "credentials": creds, "extensions": []any{ext}}
		if it.Favorite {
			entry["favorite"] = true
		}
		if len(urls) > 0 {
			entry["scope"] = cxfScope{URLs: urls, AndroidApps: []json.RawMessage{}}
		}
		out = append(out, entry)
		if sp := strings.TrimSpace(it.Space); sp != "" {
			c, ok := spaces[strings.ToLower(sp)]
			if !ok {
				c = &cxfCollection{ID: cxfID("space", strings.ToLower(sp)), Title: sp}
				spaces[strings.ToLower(sp)] = c
				spaceOrder = append(spaceOrder, strings.ToLower(sp))
			}
			c.Items = append(c.Items, cxfLinkedItem{Item: id})
		}
	}
	for _, k := range spaceOrder {
		acct.Collections = append(acct.Collections, *spaces[k])
	}
	doc := map[string]any{
		"version":             cxfVersion{Major: 1, Minor: 0},
		"exporterRpId":        cxfExporterRpID,
		"exporterDisplayName": "APM",
		"timestamp":           created.Unix(),
		"accounts": []any{map[string]any{
			"id": acct.ID, "username": "", "email": "", "fullName": acct.FullName,
			"collections": acct.Collections, "items": out,
		}},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func cxfCustomFields(it TransferItem, skip ...string) map[string]any {
	spec, _ := ItemTypeByID(it.Type)
	keys := []string{}
	for k := range it.Fields {
		if k == spec.TitleKey || containsString(skip, k) || fieldText(it.Fields[k]) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fieldOrder(it.Type, keys[i]) < fieldOrder(it.Type, keys[j]) })
	fields := []*cxfField{}
	for _, k := range keys {
		t := "string"
		if isSecretField(it.Type, k) {
			t = "concealed-string"
		}
		val := fieldText(it.Fields[k])
		if list := toStringList(it.Fields[k]); len(list) > 1 {
			val = strings.Join(list, "\n")
		}
		fields = append(fields, &cxfField{FieldType: t, Label: FieldLabel(it.Type, k), Value: val})
	}
	return map[string]any{"type": "custom-fields", "label": TypeLabel(it.Type), "fields": fields}
}

func apmCardExpiryToCXF(s string) string {
	s = strings.TrimSpace(s)
	m, y, ok := strings.Cut(s, "/")
	if !ok {
		return ""
	}
	m, y = strings.TrimSpace(m), strings.TrimSpace(y)
	if len(y) == 2 {
		y = "20" + y
	}
	if len(m) == 1 {
		m = "0" + m
	}
	if len(y) != 4 || len(m) != 2 {
		return ""
	}
	return y + "-" + m
}

func cxfSSHCredential(pemText, title string) (map[string]any, bool) {
	raw, err := ssh.ParseRawPrivateKey([]byte(strings.TrimSpace(pemText)))
	if err != nil {
		return nil, false
	}
	var key crypto.PrivateKey = raw
	if p, ok := raw.(*ed25519.PrivateKey); ok {
		key = *p
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, false
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, false
	}
	return map[string]any{"type": "ssh-key", "keyType": signer.PublicKey().Type(), "privateKey": base64.RawURLEncoding.EncodeToString(der)}, true
}
