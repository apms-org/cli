package apm

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Transfer is the import and export engine shared by `pm import`, `pm export`
// and the desktop app. Every format parses into a TransferSet of normalized
// items, the planner compares that set with the vault, and ApplyTransfer
// writes only the rows the caller decided to take.

const (
	TransferNeedsPassword    = "needs_password"
	TransferWrongPassword    = "wrong_password"
	TransferUnsupported      = "unsupported"
	TransferEmpty            = "empty"
	TransferInvalid          = "invalid"
	TransferAccountEncrypted = "account_encrypted"
)

type TransferError struct {
	Code    string
	Message string
}

func (e *TransferError) Error() string { return e.Message }

func transferErr(code, format string, a ...any) *TransferError {
	return &TransferError{Code: code, Message: fmt.Sprintf(format, a...)}
}

func TransferErrorCode(err error) string {
	var te *TransferError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

// TransferVersion is an earlier state of an item, such as a previous password.
// Fields holds only what differed; the rest is taken from the item.
type TransferVersion struct {
	Fields map[string]any
	At     time.Time
}

type TransferFile struct {
	Name string
	Data []byte
}

type DroppedPasskey struct {
	RPID     string `json:"rpId"`
	UserName string `json:"userName"`
	Reason   string `json:"reason"`
}

// TransferItem is one vault item in APM terms. Fields uses the same keys as
// ItemFields and SetItemFields, so it can be added with Vault.AddItem as is.
type TransferItem struct {
	Type     string
	Title    string
	Fields   map[string]any
	Passkeys []Passkey
	Dropped  []DroppedPasskey
	Folder   string
	Space    string
	HasSpace bool
	Favorite bool
	File     *TransferFile
	History  []TransferVersion
	Extra    []string
	Warnings []string
	Problems []string
	Link     int
}

func NewTransferItem(typ, title string) TransferItem {
	return TransferItem{Type: typ, Title: strings.TrimSpace(title), Fields: map[string]any{}, Link: -1}
}

func (it *TransferItem) Set(key string, value any) {
	if it.Fields == nil {
		it.Fields = map[string]any{}
	}
	switch t := value.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return
		}
	case []string:
		if len(t) == 0 {
			return
		}
	case nil:
		return
	}
	it.Fields[key] = value
}

func (it *TransferItem) Get(key string) string {
	if it.Fields == nil {
		return ""
	}
	return strings.TrimSpace(fieldText(it.Fields[key]))
}

// Note keeps a value the APM type has no field for. It ends up in the login's
// notes, the note's content, or a companion secure note for other types.
func (it *TransferItem) Note(label, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	label = strings.TrimSpace(label)
	if label == "" {
		it.Extra = append(it.Extra, value)
		return
	}
	if strings.Contains(value, "\n") {
		it.Extra = append(it.Extra, label+":\n"+value)
		return
	}
	it.Extra = append(it.Extra, label+": "+value)
}

func (it *TransferItem) Warn(format string, a ...any) {
	it.Warnings = append(it.Warnings, fmt.Sprintf(format, a...))
}

func (it *TransferItem) Problem(format string, a ...any) {
	it.Problems = append(it.Problems, fmt.Sprintf(format, a...))
}

func (it *TransferItem) DropPasskey(rpID, userName, reason string) {
	it.Dropped = append(it.Dropped, DroppedPasskey{RPID: rpID, UserName: userName, Reason: reason})
}

type TransferSet struct {
	Format      string
	FormatLabel string
	Vendor      string
	Encrypted   bool
	Items       []TransferItem
	Warnings    []string
}

func (s *TransferSet) Add(it TransferItem) int {
	if it.Fields == nil {
		it.Fields = map[string]any{}
	}
	s.Items = append(s.Items, it)
	return len(s.Items) - 1
}

func (s *TransferSet) Warn(format string, a ...any) {
	s.Warnings = append(s.Warnings, fmt.Sprintf(format, a...))
}

// AddTOTP splits a one-time code out of a login into its own authenticator
// item, linked to the login row and its website.
func (s *TransferSet) AddTOTP(parent int, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || parent < 0 || parent >= len(s.Items) {
		return
	}
	p := &s.Items[parent]
	item := NewTransferItem("totp", p.Title)
	item.Folder, item.Space, item.HasSpace, item.Link = p.Folder, p.Space, p.HasSpace, parent
	secret, problem := TOTPSecretFrom(raw)
	if problem != "" {
		item.Problem("%s", problem)
	}
	item.Set("secret", secret)
	if host := normalizeDomain(p.Get("website")); host != "" {
		item.Set("domain", host)
	}
	s.Add(item)
}

func (s *TransferSet) Counts() TransferCounts {
	c := TransferCounts{ByType: map[string]int{}}
	for _, it := range s.Items {
		c.Items++
		c.ByType[it.Type]++
		c.Passkeys += len(it.Passkeys)
		c.DroppedPasskeys += len(it.Dropped)
		if len(it.Problems) > 0 {
			c.Problems++
		}
	}
	return c
}

type TransferCounts struct {
	Items           int            `json:"items"`
	ByType          map[string]int `json:"byType"`
	Passkeys        int            `json:"passkeys"`
	DroppedPasskeys int            `json:"droppedPasskeys"`
	Problems        int            `json:"problems"`
}

// finish settles every item after a parser is done: titles, notes that do not
// fit the type, and validation of fields that must hold a usable value.
func (s *TransferSet) finish() {
	n := len(s.Items)
	for i := 0; i < n; i++ {
		it := &s.Items[i]
		if it.Fields == nil {
			it.Fields = map[string]any{}
		}
		spec, ok := ItemTypeByID(it.Type)
		if !ok {
			it.Problem("APM has no %q item type", it.Type)
			continue
		}
		if strings.TrimSpace(it.Title) == "" {
			it.Title = fallbackTitle(it)
		}
		it.Title = strings.TrimSpace(it.Title)
		if it.Title == "" {
			it.Problem("It has no name")
		}
		it.Fields[spec.TitleKey] = it.Title
		if len(it.Extra) > 0 {
			extra := strings.Join(it.Extra, "\n")
			switch it.Type {
			case "password":
				it.Fields["notes"] = joinNotes(it.Get("notes"), extra)
			case "note":
				it.Fields["content"] = joinNotes(it.Get("content"), extra)
			default:
				note := NewTransferItem("note", it.Title+" notes")
				note.Folder, note.Space, note.HasSpace, note.Link = it.Folder, it.Space, it.HasSpace, i
				note.Fields["content"] = extra
				note.Fields["name"] = note.Title
				s.Items = append(s.Items, note)
				it = &s.Items[i]
			}
			it.Extra = nil
		}
		switch it.Type {
		case "totp":
			if it.Get("secret") == "" && len(it.Problems) == 0 {
				it.Problem("It has no setup key")
			}
		case "password":
			if it.Get("password") == "" && it.Get("username") == "" && len(it.Passkeys) == 0 && it.Get("notes") == "" && it.Get("website") == "" {
				it.Problem("It has no username, password, website or passkey")
			}
			if urls := toStringList(it.Fields["urls"]); len(urls) > 0 {
				it.Fields["urls"] = uniqueStrings(urls, it.Get("website"))
				if len(it.Fields["urls"].([]string)) == 0 {
					delete(it.Fields, "urls")
				}
			}
		}
		if spec.Media && (it.File == nil || len(it.File.Data) == 0) {
			it.Problem("The file itself is not in this export")
		}
	}
}

func fallbackTitle(it *TransferItem) string {
	for _, k := range []string{"website", "domain", "username", "service", "host", "ssid", "email"} {
		if v := it.Get(k); v != "" {
			if h := normalizeDomain(v); k == "website" && h != "" {
				return h
			}
			return v
		}
	}
	if len(it.Passkeys) > 0 {
		return it.Passkeys[0].RPID
	}
	return ""
}

func joinNotes(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "" || strings.Contains(a, b):
		return a
	}
	return a + "\n\n" + b
}

func uniqueStrings(list []string, skip string) []string {
	seen := map[string]bool{strings.ToLower(strings.TrimSpace(skip)): true}
	out := []string{}
	for _, s := range list {
		s = strings.TrimSpace(s)
		k := strings.ToLower(s)
		if s == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

// Formats

type TransferFormat struct {
	ID     string
	Label  string
	Vendor string
	Ext    []string
	Help   string
	Detect func(name string, data []byte) int
	Parse  func(name string, data []byte, password string) (*TransferSet, error)
}

type TransferExporter struct {
	ID         string
	Label      string
	Vendor     string
	Ext        string
	Help       string
	Passkeys   bool
	Encryption bool
	Files      bool
	Secrets    bool
	Types      []string
	// SkipPasskey returns why the format cannot carry a passkey, or "".
	SkipPasskey func(Passkey) string
	Write       func(items []TransferItem, opt ExportOptions) ([]byte, error)
}

var (
	transferFormats   []TransferFormat
	transferExporters []TransferExporter
)

func RegisterTransferFormat(f TransferFormat) { transferFormats = append(transferFormats, f) }

func RegisterTransferExporter(e TransferExporter) {
	transferExporters = append(transferExporters, e)
}

func TransferFormats() []TransferFormat {
	out := append([]TransferFormat(nil), transferFormats...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor+out[i].Label < out[j].Vendor+out[j].Label })
	return out
}

func TransferExporters() []TransferExporter {
	order := map[string]int{"apm": 0, "cxf": 1, "bitwarden": 2, "csv": 3, "txt": 4}
	out := append([]TransferExporter(nil), transferExporters...)
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].ID] < order[out[j].ID] })
	return out
}

func TransferExporterByID(id string) (TransferExporter, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	switch id {
	case "", "json", "native":
		id = "apm"
	case "bitwarden-json", "bw":
		id = "bitwarden"
	case "fido", "cxp":
		id = "cxf"
	case "text":
		id = "txt"
	}
	for _, e := range transferExporters {
		if e.ID == id {
			return e, true
		}
	}
	return TransferExporter{}, false
}

// Vendor hints accepted by --from and the desktop source picker.
func transferVendor(hint string) string {
	h := strings.ToLower(strings.TrimSpace(hint))
	h = strings.NewReplacer(" ", "", "-", "", "_", "").Replace(h)
	switch h {
	case "", "auto":
		return ""
	case "1password", "onepassword", "1p", "1pux":
		return "1password"
	case "bitwarden", "bw", "vaultwarden":
		return "bitwarden"
	case "keepass", "keepassxc", "kdbx", "keepassx":
		return "keepass"
	case "cxf", "cxp", "fido", "credentialexchange":
		return "cxf"
	case "apm", "pm", "native":
		return "apm"
	case "chrome", "edge", "brave", "firefox", "safari", "browser", "csv", "txt", "text", "generic", "otpauth":
		return "generic"
	}
	return h
}

func ParseTransfer(name string, data []byte, password, hint string) (*TransferSet, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, transferErr(TransferEmpty, "%s is empty.", filepath.Base(name))
	}
	if msg := unsupportedContainer(name, data); msg != "" {
		return nil, transferErr(TransferUnsupported, "%s", msg)
	}
	vendor := transferVendor(hint)
	best, bestScore := -1, 0
	for i, f := range transferFormats {
		if vendor != "" && f.Vendor != vendor {
			continue
		}
		if score := f.Detect(name, data); score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		if vendor != "" {
			return nil, transferErr(TransferUnsupported, "%s does not look like a %s export.", filepath.Base(name), vendorLabel(vendor))
		}
		return nil, transferErr(TransferUnsupported, "APM does not recognize %s. It reads APM, 1Password (.1pux, .csv), Bitwarden (.json, .csv), KeePass (.xml, .csv), Credential Exchange (.json) and browser CSV exports.", filepath.Base(name))
	}
	f := transferFormats[best]
	set, err := f.Parse(name, data, password)
	if err != nil {
		// Callers show which format asked for a password or failed.
		return &TransferSet{Format: f.ID, FormatLabel: f.Label, Vendor: f.Vendor}, err
	}
	if set.Format == "" {
		set.Format = f.ID
	}
	if set.FormatLabel == "" {
		set.FormatLabel = f.Label
	}
	if set.Vendor == "" {
		set.Vendor = f.Vendor
	}
	set.finish()
	if len(set.Items) == 0 {
		return set, transferErr(TransferEmpty, "No items were found in %s.", filepath.Base(name))
	}
	return set, nil
}

func vendorLabel(v string) string {
	switch v {
	case "1password":
		return "1Password"
	case "bitwarden":
		return "Bitwarden"
	case "keepass":
		return "KeePass"
	case "cxf":
		return "Credential Exchange"
	case "apm":
		return "APM"
	}
	return "supported"
}

func unsupportedContainer(name string, data []byte) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case len(data) >= 8 && bytes.Equal(data[:4], []byte{0x03, 0xd9, 0xa2, 0x9a}) && bytes.Equal(data[4:8], []byte{0x67, 0xfb, 0x4b, 0xb5}), ext == ".kdbx", ext == ".kdb":
		return "This is a KeePass database file. In KeePassXC choose Database > Export > XML File, or in KeePass choose File > Export > KeePass XML (2.x), then import that file. Passkeys stored by KeePassXC come along."
	case ext == ".1pif":
		return "1PIF is the old 1Password 7 format. In 1Password 8 choose File > Export, pick the account and the 1PUX format, then import the .1pux file."
	case ext == ".opvault" || ext == ".agilekeychain":
		return "This is a 1Password vault folder, not an export. In 1Password 8 choose File > Export and the 1PUX format."
	}
	return ""
}

// Vault to transfer items

type ExportSelection struct {
	IDs      []string
	Types    []string
	Spaces   []string
	Passkeys bool
	Files    bool
}

type ExportOptions struct {
	Password  string
	Secrets   bool
	VaultName string
	Created   time.Time
}

func spaceKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "default" {
		return ""
	}
	return s
}

func (v *Vault) isFavoriteID(id string) bool {
	if v.Desktop == nil {
		return false
	}
	for _, f := range v.Desktop.Favorites {
		if f == id {
			return true
		}
	}
	return false
}

func (v *Vault) CollectTransferItems(sel ExportSelection) []TransferItem {
	ids := map[string]bool{}
	for _, id := range sel.IDs {
		ids[id] = true
	}
	types := map[string]bool{}
	for _, t := range sel.Types {
		types[strings.ToLower(strings.TrimSpace(t))] = true
	}
	spaces := map[string]bool{}
	for _, s := range sel.Spaces {
		spaces[spaceKey(s)] = true
	}
	out := []TransferItem{}
	for _, ref := range v.ItemRefs() {
		if len(ids) > 0 && !ids[ref.ID] {
			continue
		}
		if len(types) > 0 && !types[ref.Spec.ID] {
			continue
		}
		if len(spaces) > 0 && !spaces[spaceKey(ref.Space)] {
			continue
		}
		it := NewTransferItem(ref.Spec.ID, ref.Title)
		it.Fields = v.ItemRecordFields(ref)
		delete(it.Fields, "file")
		it.Space, it.HasSpace = ref.Space, true
		it.Favorite = v.isFavoriteID(ref.ID)
		if ref.Spec.Media {
			name, data, _ := v.ItemFileContent(ref)
			it.File = &TransferFile{Name: name}
			if sel.Files {
				it.File.Data = append([]byte(nil), data...)
			}
		}
		if sel.Passkeys {
			it.Passkeys = append([]Passkey(nil), v.ItemPasskeys(ref)...)
		}
		out = append(out, it)
	}
	return out
}

type ExportExclusion struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type ExportSummary struct {
	Format     string            `json:"format"`
	Label      string            `json:"label"`
	Items      int               `json:"items"`
	ByType     map[string]int    `json:"byType"`
	Passkeys   int               `json:"passkeys"`
	Files      int               `json:"files"`
	Encrypted  bool              `json:"encrypted"`
	Excluded   []ExportExclusion `json:"excluded"`
	Selected   int               `json:"selected"`
	Extension  string            `json:"ext"`
	Supports   map[string]bool   `json:"supports"`
	TypesAllow []string          `json:"types,omitempty"`
}

// PlanExport collects the selection and drops what the format cannot hold,
// saying why, so the caller can show it before anything is written.
func (v *Vault) PlanExport(format string, sel ExportSelection, opt ExportOptions) (TransferExporter, []TransferItem, ExportSummary, error) {
	ex, ok := TransferExporterByID(format)
	if !ok {
		return ex, nil, ExportSummary{}, transferErr(TransferUnsupported, "Unknown export format %q.", format)
	}
	wantPasskeys, wantFiles := sel.Passkeys, sel.Files
	sel.Passkeys = sel.Passkeys && ex.Passkeys
	sel.Files = sel.Files && ex.Files
	all := v.CollectTransferItems(sel)
	if ex.ID != "apm" {
		all = splitLoginExtras(all)
	}
	sum := ExportSummary{Format: ex.ID, Label: ex.Label, ByType: map[string]int{}, Selected: len(all), Extension: ex.Ext, Encrypted: ex.Encryption && opt.Password != "", TypesAllow: ex.Types,
		Supports: map[string]bool{"passkeys": ex.Passkeys, "encryption": ex.Encryption, "files": ex.Files, "secrets": ex.Secrets}}
	allowed := map[string]bool{}
	for _, t := range ex.Types {
		allowed[t] = true
	}
	byReason := map[string]int{}
	var reasons []string
	exclude := func(reason string, n int) {
		if n <= 0 {
			return
		}
		if _, seen := byReason[reason]; !seen {
			reasons = append(reasons, reason)
		}
		byReason[reason] += n
	}
	items := []TransferItem{}
	for _, it := range all {
		if len(allowed) > 0 && !allowed[it.Type] {
			exclude(ex.Label+" cannot hold "+typePlural(it.Type), 1)
			continue
		}
		spec, _ := ItemTypeByID(it.Type)
		if spec.Media && !sel.Files {
			if ex.Files {
				exclude("Files are left out. Turn on files to include them", 1)
			} else {
				exclude(ex.Label+" cannot hold files", 1)
			}
			continue
		}
		if ex.SkipPasskey != nil && len(it.Passkeys) > 0 {
			keep := it.Passkeys[:0:0]
			for _, pk := range it.Passkeys {
				if why := ex.SkipPasskey(pk); why != "" {
					exclude(why, 1)
					continue
				}
				keep = append(keep, pk)
			}
			it.Passkeys = keep
		}
		items = append(items, it)
		sum.ByType[it.Type]++
		sum.Passkeys += len(it.Passkeys)
		if it.File != nil && len(it.File.Data) > 0 {
			sum.Files++
		}
	}
	if !sel.Passkeys {
		n := 0
		for _, ref := range v.ItemRefs() {
			if ref.Spec.ID == "password" && (len(sel.IDs) == 0 || containsString(sel.IDs, ref.ID)) {
				n += len(v.ItemPasskeys(ref))
			}
		}
		if n > 0 {
			if !ex.Passkeys {
				exclude(ex.Label+" cannot hold passkeys", n)
			} else if !wantPasskeys {
				exclude("Passkeys are left out", n)
			}
		}
	}
	_ = wantFiles
	for _, r := range reasons {
		sum.Excluded = append(sum.Excluded, ExportExclusion{Reason: r, Count: byReason[r]})
	}
	sum.Items = len(items)
	return ex, items, sum, nil
}

func (v *Vault) ExportTransfer(format string, sel ExportSelection, opt ExportOptions) ([]byte, ExportSummary, error) {
	ex, items, sum, err := v.PlanExport(format, sel, opt)
	if err != nil {
		return nil, sum, err
	}
	if len(items) == 0 {
		return nil, sum, transferErr(TransferEmpty, "Nothing to export. The selection has no items %s can hold.", ex.Label)
	}
	if opt.Created.IsZero() {
		opt.Created = time.Now()
	}
	if !ex.Encryption {
		opt.Password = ""
	}
	data, err := ex.Write(items, opt)
	return data, sum, err
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func typePlural(id string) string {
	names := map[string]string{"password": "logins", "totp": "authenticator codes", "note": "secure notes", "wifi": "Wi-Fi networks", "govid": "government IDs", "medical": "medical records", "travel": "travel documents", "contact": "contacts", "recovery": "recovery codes", "apikey": "API keys", "token": "tokens", "ssh_key": "SSH keys", "ssh_config": "SSH hosts", "cloud": "cloud credentials", "k8s": "Kubernetes secrets", "docker": "Docker registries", "cicd": "CI/CD secrets", "certificate": "certificates", "banking": "cards and accounts", "license": "software licenses", "legal": "legal contracts", "document": "documents", "photo": "photos", "audio": "audio files", "video": "videos"}
	if n, ok := names[id]; ok {
		return n
	}
	return id + " items"
}

func TypeLabel(id string) string {
	names := map[string]string{"password": "Login", "totp": "Authenticator", "note": "Secure note", "wifi": "Wi-Fi", "govid": "Government ID", "medical": "Medical record", "travel": "Travel", "contact": "Contact", "recovery": "Recovery codes", "apikey": "API key", "token": "Token", "ssh_key": "SSH key", "ssh_config": "SSH host", "cloud": "Cloud credentials", "k8s": "Kubernetes", "docker": "Docker registry", "cicd": "CI/CD secret", "certificate": "Certificate", "banking": "Card or account", "license": "Software license", "legal": "Legal contract", "document": "Document", "photo": "Photo", "audio": "Audio", "video": "Video"}
	if n, ok := names[id]; ok {
		return n
	}
	return id
}
