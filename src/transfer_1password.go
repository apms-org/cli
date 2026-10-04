package apm

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 1Password exports: the full-fidelity .1pux zip and the logins-only CSV.
// 1PUX never carries passkeys; 1Password only moves those with Credential
// Exchange on iOS and Android.

func init() {
	RegisterTransferFormat(TransferFormat{
		ID: "1password-1pux", Label: "1Password export (.1pux)", Vendor: "1password", Ext: []string{".1pux"},
		Help:   "In 1Password 8 choose File > Export, pick the account, then the 1PUX format. 1Password leaves passkeys out of every export.",
		Detect: detect1PUX, Parse: parse1PUX,
	})
	RegisterTransferFormat(TransferFormat{
		ID: "1password-csv", Label: "1Password CSV", Vendor: "1password", Ext: []string{".csv"},
		Help:   "In 1Password 8 choose File > Export and the CSV format. CSV holds logins and passwords only; use 1PUX to bring everything else.",
		Detect: detect1PasswordCSV, Parse: parse1PasswordCSV,
	})
}

const onePasswordPasskeyNote = "1Password leaves passkeys out of .1pux exports. To move them, use 1Password on iOS or Android to transfer them with Credential Exchange (for example into Bitwarden), then import a Bitwarden export here."

func zipHasEntry(data []byte, name string) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if f.Name == name {
			return true
		}
	}
	return false
}

func detect1PUX(name string, data []byte) int {
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return 0
	}
	if zipHasEntry(data, "export.data") {
		return 100
	}
	if strings.EqualFold(filepath.Ext(name), ".1pux") {
		return 60
	}
	return 0
}

type flexNum float64

func (n *flexNum) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*n = 0
		return nil
	}
	*n = flexNum(f)
	return nil
}

type opuxDoc struct {
	Accounts []struct {
		Attrs struct {
			AccountName string `json:"accountName"`
			Name        string `json:"name"`
		} `json:"attrs"`
		Vaults []struct {
			Attrs struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"attrs"`
			Items []opuxItem `json:"items"`
		} `json:"vaults"`
	} `json:"accounts"`
}

type opuxItem struct {
	UUID         string  `json:"uuid"`
	FavIndex     flexNum `json:"favIndex"`
	State        string  `json:"state"`
	Trashed      bool    `json:"trashed"`
	CategoryUUID string  `json:"categoryUuid"`
	Overview     struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		URLs  []struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"urls"`
		Tags []string `json:"tags"`
	} `json:"overview"`
	Details struct {
		LoginFields []struct {
			Value       string `json:"value"`
			ID          string `json:"id"`
			Name        string `json:"name"`
			FieldType   string `json:"fieldType"`
			Type        string `json:"type"`
			Designation string `json:"designation"`
		} `json:"loginFields"`
		NotesPlain string `json:"notesPlain"`
		Sections   []struct {
			Title  string `json:"title"`
			Name   string `json:"name"`
			Fields []struct {
				Title string                     `json:"title"`
				ID    string                     `json:"id"`
				Value map[string]json.RawMessage `json:"value"`
			} `json:"fields"`
		} `json:"sections"`
		PasswordHistory []struct {
			Value string  `json:"value"`
			Time  flexNum `json:"time"`
		} `json:"passwordHistory"`
		DocumentAttributes *struct {
			FileName   string `json:"fileName"`
			DocumentID string `json:"documentId"`
		} `json:"documentAttributes"`
		Password string `json:"password"`
	} `json:"details"`
}

// opField is one decoded section field.
type opField struct {
	id, title, kind, text string
	month                 int
	sshKey                string
	fileName, fileID      string
	used                  bool
}

type opFields []*opField

// take returns the first unused field matching any of the ids or titles.
func (fs opFields) take(names ...string) *opField {
	for _, n := range names {
		for _, f := range fs {
			if f.used || f.text == "" && f.sshKey == "" {
				continue
			}
			if strings.EqualFold(f.id, n) || strings.EqualFold(f.title, n) {
				f.used = true
				return f
			}
		}
	}
	return nil
}

func (fs opFields) text(names ...string) string {
	if f := fs.take(names...); f != nil {
		return f.text
	}
	return ""
}

func rawString(b json.RawMessage) string {
	var s string
	if json.Unmarshal(b, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(b, &n) == nil {
		return n.String()
	}
	return ""
}

func decodeOPValue(v map[string]json.RawMessage, f *opField) {
	for kind, raw := range v {
		f.kind = kind
		switch kind {
		case "email":
			var e struct {
				Address string `json:"email_address"`
			}
			if json.Unmarshal(raw, &e) == nil && e.Address != "" {
				f.text = e.Address
			} else {
				f.text = rawString(raw)
			}
		case "address":
			var a struct {
				Street, City, State, Zip, Country string
			}
			if json.Unmarshal(raw, &a) == nil {
				parts := []string{}
				for _, p := range []string{a.Street, strings.TrimSpace(a.City + " " + a.State + " " + a.Zip), a.Country} {
					if strings.TrimSpace(p) != "" {
						parts = append(parts, strings.TrimSpace(p))
					}
				}
				f.text = strings.Join(parts, "\n")
			}
		case "date":
			var n flexNum
			if json.Unmarshal(raw, &n) == nil && n != 0 {
				f.text = time.Unix(int64(n), 0).UTC().Format("2006-01-02")
			}
		case "monthYear":
			var n flexNum
			if json.Unmarshal(raw, &n) == nil && n > 0 {
				f.month = int(n)
				f.text = fmt.Sprintf("%02d/%04d", f.month%100, f.month/100)
			}
		case "sshKey":
			var k struct {
				PrivateKey string `json:"privateKey"`
				Metadata   struct {
					PrivateKey string `json:"privateKey"`
				} `json:"metadata"`
			}
			if json.Unmarshal(raw, &k) == nil {
				f.sshKey = firstNonEmpty(k.Metadata.PrivateKey, k.PrivateKey)
			}
		case "file":
			var fl struct {
				FileName   string `json:"fileName"`
				DocumentID string `json:"documentId"`
			}
			if json.Unmarshal(raw, &fl) == nil {
				f.fileName, f.fileID = fl.FileName, fl.DocumentID
			}
		default:
			f.text = rawString(raw)
		}
		f.text = strings.TrimSpace(f.text)
		return
	}
}

func cardExpiry(f *opField) string {
	if f == nil {
		return ""
	}
	if f.month > 0 {
		return fmt.Sprintf("%02d/%02d", f.month%100, (f.month/100)%100)
	}
	return f.text
}

var ibanRe = regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$`)

func parse1PUX(name string, data []byte, password string) (*TransferSet, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, transferErr(TransferInvalid, "The .1pux file is not a readable zip archive.")
	}
	files := map[string]*zip.File{}
	var docFile *zip.File
	for _, f := range zr.File {
		if f.Name == "export.data" {
			docFile = f
		}
		if strings.HasPrefix(f.Name, "files/") {
			files[strings.TrimPrefix(f.Name, "files/")] = f
		}
	}
	if docFile == nil {
		return nil, transferErr(TransferInvalid, "The .1pux file has no export.data inside.")
	}
	rc, err := docFile.Open()
	if err != nil {
		return nil, transferErr(TransferInvalid, "The .1pux file is damaged.")
	}
	raw, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, transferErr(TransferInvalid, "The .1pux file is damaged.")
	}
	var doc opuxDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, transferErr(TransferInvalid, "The .1pux export.data is not valid JSON.")
	}
	readFile := func(id, fileName string) []byte {
		f := files[id+"__"+fileName]
		if f == nil && id != "" {
			for k, v := range files {
				if strings.HasPrefix(k, id) {
					f = v
					break
				}
			}
		}
		if f == nil {
			return nil
		}
		r, err := f.Open()
		if err != nil {
			return nil
		}
		defer r.Close()
		b, _ := io.ReadAll(r)
		return b
	}
	vaults := 0
	for _, a := range doc.Accounts {
		vaults += len(a.Vaults)
	}
	set := &TransferSet{Format: "1password-1pux", FormatLabel: "1Password export (.1pux)", Vendor: "1password"}
	trashed, logins := 0, 0
	for _, a := range doc.Accounts {
		for _, vlt := range a.Vaults {
			folder := ""
			if vaults > 1 {
				folder = strings.TrimSpace(vlt.Attrs.Name)
			}
			for i := range vlt.Items {
				x := &vlt.Items[i]
				state := strings.ToLower(x.State)
				if x.Trashed || state == "trashed" || state == "deleted" {
					trashed++
					continue
				}
				if x.CategoryUUID == "001" || x.CategoryUUID == "005" {
					logins++
				}
				add1PUXItem(set, x, folder, state == "archived", readFile)
			}
		}
	}
	if trashed > 0 {
		set.Warn("%s in 1Password's trash %s left out.", plural(trashed, "item"), map[bool]string{true: "was", false: "were"}[trashed == 1])
	}
	if logins > 0 {
		set.Warn("%s", onePasswordPasskeyNote)
	}
	return set, nil
}

func add1PUXItem(set *TransferSet, x *opuxItem, folder string, archived bool, readFile func(id, name string) []byte) {
	fields := opFields{}
	sectionName := map[*opField]string{}
	for _, s := range x.Details.Sections {
		for _, sf := range s.Fields {
			f := &opField{id: sf.ID, title: strings.TrimSpace(sf.Title)}
			decodeOPValue(sf.Value, f)
			fields = append(fields, f)
			sectionName[f] = strings.TrimSpace(s.Title)
		}
	}
	title := strings.TrimSpace(x.Overview.Title)
	notes := strings.TrimSpace(x.Details.NotesPlain)
	var it TransferItem
	setNotes := true
	switch x.CategoryUUID {
	case "001", "005":
		it = NewTransferItem("password", title)
		for _, lf := range x.Details.LoginFields {
			v := strings.TrimSpace(lf.Value)
			if v == "" {
				continue
			}
			switch strings.ToLower(lf.Designation) {
			case "username":
				it.Set("username", v)
			case "password":
				it.Set("password", v)
			default:
				ft := strings.ToUpper(firstNonEmpty(lf.FieldType, lf.Type))
				if ft == "T" || ft == "E" || ft == "P" || ft == "U" || ft == "N" || ft == "TEL" || ft == "A" {
					it.Note(firstNonEmpty(lf.Name, lf.ID), v)
				}
			}
		}
		if it.Get("password") == "" {
			it.Set("password", firstNonEmpty(x.Details.Password, fields.text("password")))
		}
		if it.Get("username") == "" {
			it.Set("username", fields.text("username"))
		}
		urls := []string{}
		if u := strings.TrimSpace(x.Overview.URL); u != "" {
			urls = append(urls, u)
		}
		for _, u := range x.Overview.URLs {
			if s := strings.TrimSpace(u.URL); s != "" && !containsString(urls, s) {
				urls = append(urls, s)
			}
		}
		if len(urls) > 0 {
			it.Set("website", urls[0])
			if len(urls) > 1 {
				it.Set("urls", urls[1:])
			}
		}
		it.Set("notes", notes)
		setNotes = false
		for _, h := range x.Details.PasswordHistory {
			if strings.TrimSpace(h.Value) == "" || h.Value == it.Get("password") {
				continue
			}
			it.History = append(it.History, TransferVersion{Fields: map[string]any{"password": h.Value}, At: time.Unix(int64(h.Time), 0)})
		}
	case "002":
		it = NewTransferItem("banking", title)
		it.Set("type", "Card")
		it.Set("details", fields.text("ccnum", "card number", "number"))
		it.Set("cvv", fields.text("cvv", "verification number"))
		it.Set("expiry", cardExpiry(fields.take("expiry", "expiry date", "expires")))
	case "003":
		it = NewTransferItem("note", title)
		it.Set("content", notes)
		setNotes = false
	case "004":
		it = NewTransferItem("contact", title)
		first, last := fields.text("firstname", "first name"), fields.text("lastname", "last name")
		if full := strings.TrimSpace(first + " " + last); full != "" && full != title {
			it.Note("Name", full)
		}
		it.Set("phone", fields.text("defphone", "cellphone", "homephone", "busphone", "phone"))
		it.Set("email", fields.text("email"))
		it.Set("address", fields.text("address"))
	case "006":
		it = NewTransferItem("document", title)
		if d := x.Details.DocumentAttributes; d != nil {
			it.File = &TransferFile{Name: d.FileName, Data: readFile(d.DocumentID, d.FileName)}
		}
	case "100":
		it = NewTransferItem("license", title)
		it.Set("serial_key", fields.text("reg_code", "license key"))
		it.Set("expiration", fields.text("expiry_date", "expiry date", "expires"))
		it.Set("activation_info", fields.text("product_version", "version"))
	case "101":
		it = NewTransferItem("banking", title)
		iban := strings.ToUpper(strings.ReplaceAll(fields.text("iban"), " ", ""))
		acct := fields.text("accountNo", "account number")
		norm := strings.ToUpper(strings.ReplaceAll(acct, " ", ""))
		switch {
		case iban != "":
			it.Set("type", "IBAN")
			it.Set("details", iban)
			it.Note("Account number", acct)
		case ibanRe.MatchString(norm):
			it.Set("type", "IBAN")
			it.Set("details", norm)
		default:
			it.Set("type", "Account")
			it.Set("details", acct)
		}
	case "102", "110", "111":
		it = NewTransferItem("password", title)
		it.Set("website", fields.text("url", "hostname", "server", "pop_server", "imap_server"))
		it.Set("username", fields.text("username", "pop_username"))
		it.Set("password", fields.text("password", "pop_password"))
		it.Set("notes", notes)
		setNotes = false
	case "103":
		it = NewTransferItem("govid", title)
		it.Set("type", "Driver's License")
		it.Set("id_number", fields.text("number", "license number"))
		it.Set("expiry", govExpiry(fields.take("expiry_date", "expiry date", "expires")))
	case "106":
		it = NewTransferItem("govid", title)
		it.Set("type", "Passport")
		it.Set("id_number", fields.text("number", "passport number"))
		it.Set("expiry", govExpiry(fields.take("expiry_date", "expiry date", "expires")))
	case "108":
		it = NewTransferItem("govid", title)
		it.Set("type", "National ID")
		it.Set("id_number", fields.text("number"))
	case "109":
		ssid := fields.text("network_name", "network name")
		it = NewTransferItem("wifi", firstNonEmpty(ssid, title))
		if ssid != "" && title != "" && ssid != title {
			it.Note("Name", title)
		}
		it.Set("password", fields.text("wireless_password", "wireless network password"))
		it.Set("security_type", fields.text("wireless_security", "wireless security"))
		if bp := fields.take("password", "base station password"); bp != nil {
			it.Note("Base station password", bp.text)
		}
	case "112":
		it = NewTransferItem("apikey", title)
		it.Set("key", fields.text("credential", "api key", "key"))
		it.Set("service", fields.text("hostname", "type"))
	case "113":
		it = NewTransferItem("medical", title)
		med := []string{}
		for {
			f := fields.take("medication")
			if f == nil {
				break
			}
			line := f.text
			if d := fields.text("dosage"); d != "" {
				line += " " + d
			}
			med = append(med, line)
		}
		it.Set("prescriptions", strings.Join(med, "\n"))
	case "114":
		it = NewTransferItem("ssh_key", title)
		for _, f := range fields {
			if !f.used && f.sshKey != "" {
				it.Set("private_key", f.sshKey)
				f.used = true
				break
			}
		}
		if it.Get("private_key") == "" {
			it.Set("private_key", fields.text("private_key", "private key"))
		}
	default:
		it = NewTransferItem("note", title)
		it.Set("content", notes)
		setNotes = false
	}
	it.Folder = folder
	it.Favorite = x.FavIndex > 0
	if archived {
		it.Warn("Archived in 1Password")
	}
	if setNotes {
		it.Note("", notes)
	}
	totps := []string{}
	type attachment struct{ name, id string }
	attachments := []attachment{}
	for _, f := range fields {
		if f.used {
			continue
		}
		switch {
		case f.kind == "totp":
			if f.text != "" {
				totps = append(totps, f.text)
			}
		case f.kind == "file":
			if f.fileName != "" {
				attachments = append(attachments, attachment{f.fileName, f.fileID})
			}
		case f.sshKey != "":
			it.Note(firstNonEmpty(f.title, "Private key"), f.sshKey)
		default:
			label := f.title
			if label == "" {
				label = sectionName[f]
			}
			it.Note(label, f.text)
		}
	}
	if len(x.Overview.Tags) > 0 {
		it.Note("Tags", strings.Join(x.Overview.Tags, ", "))
	}
	idx := set.Add(it)
	for _, t := range totps {
		set.AddTOTP(idx, t)
	}
	for _, a := range attachments {
		doc := NewTransferItem("document", title+" - "+a.name)
		doc.Folder, doc.Link, doc.Favorite = folder, idx, false
		doc.File = &TransferFile{Name: a.name, Data: readFile(a.id, a.name)}
		set.Add(doc)
	}
}

func govExpiry(f *opField) string {
	if f == nil {
		return ""
	}
	if f.month > 0 {
		return fmt.Sprintf("%04d-%02d-01", f.month/100, f.month%100)
	}
	return f.text
}

func detect1PasswordCSV(name string, data []byte) int {
	c := NewCSVColumns(csvHead(data))
	switch {
	case c.Has("title", "username", "password", "otpauth") && (c.Has("favorite") || c.Has("archived") || c.Has("tags")):
		return 80
	case c.Has("notesplain") && c.Has("title"):
		return 75
	case c.Has("uuid", "ainfo"):
		return 75
	}
	return 0
}

func parse1PasswordCSV(name string, data []byte, password string) (*TransferSet, error) {
	head, rows, err := ReadCSVTable(data)
	if err != nil {
		return nil, err
	}
	c := NewCSVColumns(head)
	set := &TransferSet{Format: "1password-csv", FormatLabel: "1Password CSV", Vendor: "1password"}
	archived := 0
	for _, row := range rows {
		it := NewTransferItem("password", c.Get(row, "title", "name"))
		urls := []string{}
		for _, u := range strings.FieldsFunc(c.Get(row, "url", "urls", "website", "scope"), func(r rune) bool { return r == '\n' || r == ' ' }) {
			if u = strings.TrimSpace(u); u != "" {
				urls = append(urls, u)
			}
		}
		if len(urls) > 0 {
			it.Set("website", urls[0])
			if len(urls) > 1 {
				it.Set("urls", urls[1:])
			}
		}
		it.Set("username", c.Get(row, "username"))
		it.Set("password", c.Get(row, "password"))
		it.Set("notes", c.Get(row, "notes", "notesplain"))
		it.Favorite = toBool(c.Get(row, "favorite"))
		if toBool(c.Get(row, "archived")) {
			it.Warn("Archived in 1Password")
			archived++
		}
		if tags := c.Get(row, "tags"); tags != "" {
			it.Note("Tags", strings.ReplaceAll(tags, ";", ", "))
		}
		idx := set.Add(it)
		if otp := c.Get(row, "otpauth", "one-time password", "otp"); otp != "" {
			set.AddTOTP(idx, otp)
		}
	}
	set.Warn("%s", "1Password CSV exports hold logins and passwords only. Export in the 1PUX format to bring notes, cards, identities and documents too. "+onePasswordPasskeyNote)
	return set, nil
}
