package apm

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KeePass XML (2.x) and CSV exports. KeePassXC keeps passkeys as entry
// attributes (KPEX_PASSKEY_*) with a PEM private key, which an XML export
// carries in plain text, so passkeys come along.

func init() {
	RegisterTransferFormat(TransferFormat{
		ID: "keepass-xml", Label: "KeePass XML", Vendor: "keepass", Ext: []string{".xml"},
		Help:   "In KeePassXC choose Database > Export > XML File. In KeePass 2 choose File > Export > KeePass XML (2.x). Passkeys saved by KeePassXC come along.",
		Detect: detectKeePassXML, Parse: parseKeePassXML,
	})
	RegisterTransferFormat(TransferFormat{
		ID: "keepass-csv", Label: "KeePass CSV", Vendor: "keepass", Ext: []string{".csv"},
		Help:   "In KeePassXC choose Database > Export > CSV File. CSV leaves out passkeys and history; export XML to keep them.",
		Detect: detectKeePassCSV, Parse: parseKeePassCSV,
	})
}

func detectKeePassXML(name string, data []byte) int {
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	if bytes.Contains(head, []byte("<KeePassFile")) {
		return 100
	}
	return 0
}

type kpValue struct {
	Protected string `xml:"Protected,attr"`
	Text      string `xml:",chardata"`
}

type kpString struct {
	Key   string  `xml:"Key"`
	Value kpValue `xml:"Value"`
}

type kpTimes struct {
	CreationTime         string `xml:"CreationTime"`
	LastModificationTime string `xml:"LastModificationTime"`
}

type kpEntry struct {
	UUID     string     `xml:"UUID"`
	Tags     string     `xml:"Tags"`
	Strings  []kpString `xml:"String"`
	Binaries []struct {
		Key string `xml:"Key"`
	} `xml:"Binary"`
	Times   kpTimes `xml:"Times"`
	History struct {
		Entries []kpEntry `xml:"Entry"`
	} `xml:"History"`
}

type kpGroup struct {
	UUID    string    `xml:"UUID"`
	Name    string    `xml:"Name"`
	Entries []kpEntry `xml:"Entry"`
	Groups  []kpGroup `xml:"Group"`
}

type kpFile struct {
	Meta struct {
		RecycleBinUUID    string `xml:"RecycleBinUUID"`
		RecycleBinEnabled string `xml:"RecycleBinEnabled"`
	} `xml:"Meta"`
	Root struct {
		Groups []kpGroup `xml:"Group"`
	} `xml:"Root"`
}

// kpTime reads either ISO 8601 (KeePass 2 export) or the KDBX 4 form: base64
// of little-endian seconds since 0001-01-01.
func kpTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 8 {
		secs := int64(binary.LittleEndian.Uint64(b))
		return time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(secs/86400) * 24 * time.Hour).Add(time.Duration(secs%86400) * time.Second)
	}
	return ParseTransferTime(s)
}

func (e *kpEntry) values() map[string]string {
	m := map[string]string{}
	for _, s := range e.Strings {
		m[s.Key] = s.Value.Text
	}
	return m
}

func parseKeePassXML(name string, data []byte, password string) (*TransferSet, error) {
	var doc kpFile
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, transferErr(TransferInvalid, "The KeePass XML could not be read: %v", err)
	}
	set := &TransferSet{Format: "keepass-xml", FormatLabel: "KeePass XML", Vendor: "keepass"}
	bin := strings.TrimSpace(doc.Meta.RecycleBinUUID)
	if strings.Trim(bin, "A=") == "" {
		bin = ""
	}
	recycled, attachments := 0, 0
	var countAll func(g *kpGroup) int
	countAll = func(g *kpGroup) int {
		n := len(g.Entries)
		for i := range g.Groups {
			n += countAll(&g.Groups[i])
		}
		return n
	}
	var walk func(g *kpGroup, path []string)
	walk = func(g *kpGroup, path []string) {
		for i := range g.Entries {
			attachments += len(g.Entries[i].Binaries)
			addKeePassEntry(set, &g.Entries[i], strings.Join(path, "/"))
		}
		for i := range g.Groups {
			sub := &g.Groups[i]
			if (bin != "" && strings.TrimSpace(sub.UUID) == bin) || strings.EqualFold(strings.TrimSpace(sub.Name), "Recycle Bin") {
				recycled += countAll(sub)
				continue
			}
			walk(sub, append(append([]string{}, path...), strings.TrimSpace(sub.Name)))
		}
	}
	for i := range doc.Root.Groups {
		walk(&doc.Root.Groups[i], nil)
	}
	if recycled > 0 {
		set.Warn("%s in the KeePass recycle bin %s left out.", plural(recycled, "entry"), map[bool]string{true: "was", false: "were"}[recycled == 1])
	}
	if attachments > 0 {
		set.Warn("%s %s not imported. Save them from KeePass and add them to APM as documents.", plural(attachments, "attachment"), map[bool]string{true: "is", false: "are"}[attachments == 1])
	}
	return set, nil
}

var kpStandard = map[string]bool{"Title": true, "UserName": true, "Password": true, "URL": true, "Notes": true}

func kpIsOTPKey(k string) bool {
	return k == "otp" || strings.HasPrefix(k, "TimeOtp-") || strings.HasPrefix(k, "HmacOtp-") || k == "TOTP Seed" || k == "TOTP Settings"
}

func kpIsExtraURL(k string) bool {
	u := strings.ToUpper(k)
	return strings.HasPrefix(u, "KP2A_URL") || (strings.HasPrefix(u, "URL_") && len(u) > 4) || strings.HasPrefix(u, "KPH: URL")
}

func addKeePassEntry(set *TransferSet, e *kpEntry, folder string) {
	vals := e.values()
	title := strings.TrimSpace(vals["Title"])
	user, pass, site, notes := strings.TrimSpace(vals["UserName"]), vals["Password"], strings.TrimSpace(vals["URL"]), strings.TrimSpace(vals["Notes"])
	otp := keepassOTP(vals)
	hasKey := strings.TrimSpace(vals["KPEX_PASSKEY_PRIVATE_KEY_PEM"]) != ""
	typ := "password"
	if user == "" && pass == "" && site == "" && otp == "" && !hasKey && notes != "" {
		typ = "note"
	}
	it := NewTransferItem(typ, title)
	it.Folder = folder
	if typ == "note" {
		it.Set("content", notes)
	} else {
		it.Set("username", user)
		it.Set("password", pass)
		it.Set("website", site)
		it.Set("notes", notes)
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	urls := []string{}
	for _, k := range keys {
		v := strings.TrimSpace(vals[k])
		switch {
		case kpStandard[k] || kpIsOTPKey(k) || strings.HasPrefix(k, "KPEX_PASSKEY_") || v == "":
		case kpIsExtraURL(k) && typ == "password":
			urls = append(urls, v)
		default:
			it.Note(k, v)
		}
	}
	if len(urls) > 0 {
		it.Set("urls", urls)
	}
	if hasKey {
		rp := strings.TrimSpace(vals["KPEX_PASSKEY_RELYING_PARTY"])
		pkUser := strings.TrimSpace(vals["KPEX_PASSKEY_USERNAME"])
		key, err := PasskeyKeyFromPEM(vals["KPEX_PASSKEY_PRIVATE_KEY_PEM"])
		if err != nil {
			it.DropPasskey(rp, pkUser, strings.ToUpper(err.Error()[:1])+err.Error()[1:])
		} else {
			it.AddPasskey(ImportedPasskey{
				RPID: rp, UserName: pkUser, UserDisplayName: pkUser,
				UserHandle: vals["KPEX_PASSKEY_USER_HANDLE"], CredentialID: vals["KPEX_PASSKEY_CREDENTIAL_ID"],
				Key: key, Created: kpTime(e.Times.CreationTime),
			})
		}
		if it.Get("website") == "" && rp != "" {
			it.Set("website", "https://"+rp)
		}
	}
	if tags := strings.TrimSpace(e.Tags); tags != "" {
		it.Note("Tags", strings.NewReplacer(";", ", ", ",", ", ").Replace(tags))
	}
	if typ == "password" {
		hist := append([]kpEntry(nil), e.History.Entries...)
		sort.SliceStable(hist, func(i, j int) bool {
			return kpTime(hist[i].Times.LastModificationTime).After(kpTime(hist[j].Times.LastModificationTime))
		})
		seen := map[string]bool{pass: true}
		for i := range hist {
			old := hist[i].values()["Password"]
			if old == "" || seen[old] {
				continue
			}
			seen[old] = true
			it.History = append(it.History, TransferVersion{Fields: map[string]any{"password": old}, At: kpTime(hist[i].Times.LastModificationTime)})
		}
	}
	idx := set.Add(it)
	if otp != "" {
		set.AddTOTP(idx, otp)
	}
}

// keepassOTP turns the ways KeePass plugins and KeePassXC store one-time
// codes into an otpauth:// link (or raw key) that TOTPSecretFrom understands.
func keepassOTP(vals map[string]string) string {
	if o := strings.TrimSpace(vals["otp"]); o != "" {
		if strings.HasPrefix(strings.ToLower(o), "otpauth://") {
			return o
		}
		if strings.Contains(o, "key=") {
			q, err := url.ParseQuery(o)
			if err == nil && q.Get("key") != "" {
				alg := "SHA1"
				switch strings.ToLower(q.Get("otpHashMode")) {
				case "sha256":
					alg = "SHA256"
				case "sha512":
					alg = "SHA512"
				}
				if strings.EqualFold(q.Get("type"), "hotp") {
					return "otpauth://hotp/x?secret=" + q.Get("key")
				}
				return otpauthURL(q.Get("key"), atoiOr(q.Get("size"), 6), atoiOr(q.Get("step"), 30), alg)
			}
		}
		return o
	}
	secret := ""
	switch {
	case vals["TimeOtp-Secret-Base32"] != "":
		secret = vals["TimeOtp-Secret-Base32"]
	case vals["TimeOtp-Secret"] != "":
		secret = base32.StdEncoding.EncodeToString([]byte(vals["TimeOtp-Secret"]))
	case vals["TimeOtp-Secret-Hex"] != "":
		if b, err := hex.DecodeString(strings.ReplaceAll(vals["TimeOtp-Secret-Hex"], " ", "")); err == nil {
			secret = base32.StdEncoding.EncodeToString(b)
		}
	case vals["TimeOtp-Secret-Base64"] != "":
		if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(vals["TimeOtp-Secret-Base64"])); err == nil {
			secret = base32.StdEncoding.EncodeToString(b)
		}
	}
	if secret != "" {
		alg := "SHA1"
		switch strings.ToUpper(strings.ReplaceAll(vals["TimeOtp-Algorithm"], "HMAC-", "")) {
		case "SHA-256", "SHA256":
			alg = "SHA256"
		case "SHA-512", "SHA512":
			alg = "SHA512"
		}
		return otpauthURL(secret, atoiOr(vals["TimeOtp-Length"], 6), atoiOr(vals["TimeOtp-Period"], 30), alg)
	}
	if seed := strings.TrimSpace(vals["TOTP Seed"]); seed != "" {
		period, digits := 30, 6
		if parts := strings.Split(vals["TOTP Settings"], ";"); len(parts) == 2 {
			period = atoiOr(parts[0], 30)
			if strings.EqualFold(strings.TrimSpace(parts[1]), "S") {
				return "steam://" + seed
			}
			digits = atoiOr(parts[1], 6)
		}
		return otpauthURL(seed, digits, period, "SHA1")
	}
	return ""
}

func otpauthURL(secret string, digits, period int, alg string) string {
	secret = strings.ReplaceAll(strings.TrimSpace(secret), " ", "")
	return fmt.Sprintf("otpauth://totp/x?secret=%s&digits=%d&period=%d&algorithm=%s", url.QueryEscape(secret), digits, period, alg)
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return def
}

func detectKeePassCSV(name string, data []byte) int {
	c := NewCSVColumns(csvHead(data))
	switch {
	case c.Has("group", "title", "username", "password", "url", "notes"):
		return 80
	case c.Has("account", "login name", "password", "web site"):
		return 80
	}
	return 0
}

func parseKeePassCSV(name string, data []byte, password string) (*TransferSet, error) {
	head, rows, err := ReadCSVTable(data)
	if err != nil {
		return nil, err
	}
	c := NewCSVColumns(head)
	set := &TransferSet{Format: "keepass-csv", FormatLabel: "KeePass CSV", Vendor: "keepass"}
	for _, row := range rows {
		folder := c.Get(row, "group")
		if i := strings.Index(folder, "/"); i >= 0 {
			folder = folder[i+1:]
		} else {
			folder = ""
		}
		if strings.HasPrefix(strings.ToLower(folder), "recycle bin") {
			continue
		}
		user, pass, site := c.Get(row, "username", "login name"), c.Get(row, "password"), c.Get(row, "url", "web site")
		notes := c.Get(row, "notes", "comments")
		otp := c.Get(row, "totp")
		typ := "password"
		if user == "" && pass == "" && site == "" && otp == "" && notes != "" {
			typ = "note"
		}
		it := NewTransferItem(typ, c.Get(row, "title", "account"))
		it.Folder = folder
		if typ == "note" {
			it.Set("content", notes)
		} else {
			it.Set("username", user)
			it.Set("password", pass)
			it.Set("website", site)
			it.Set("notes", notes)
		}
		idx := set.Add(it)
		if otp != "" {
			set.AddTOTP(idx, otp)
		}
	}
	return set, nil
}
