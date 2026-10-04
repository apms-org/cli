package apm

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Browser and generic CSV, and plain text with otpauth:// links. Vendor CSVs
// (Bitwarden, 1Password, KeePassXC) register their own formats with higher
// detection scores, so this is the fallback for everything column-shaped.

func init() {
	RegisterTransferFormat(TransferFormat{
		ID: "csv", Label: "CSV", Vendor: "generic", Ext: []string{".csv"},
		Help:   "Passwords CSV from Chrome, Edge, Brave, Firefox or Safari, or any CSV with name, url, username and password columns.",
		Detect: detectGenericCSV, Parse: parseGenericCSV,
	})
	RegisterTransferFormat(TransferFormat{
		ID: "txt", Label: "Text with otpauth:// links", Vendor: "generic", Ext: []string{".txt"},
		Help:   "One otpauth:// link per line, as authenticator apps export them, or an APM text export.",
		Detect: detectText, Parse: parseText,
	})
	RegisterTransferExporter(TransferExporter{
		ID: "csv", Label: "CSV", Vendor: "generic", Ext: "csv", Secrets: true,
		Help:  "One row per item with name, url, username, password and note columns, which Chrome, Firefox, Safari and most managers read. Passkeys and files cannot be stored in CSV.",
		Write: writeCSVExport,
	})
	RegisterTransferExporter(TransferExporter{
		ID: "txt", Label: "Text", Vendor: "generic", Ext: "txt", Secrets: true,
		Help:  "A readable list of every item. Leave secrets out for a printable inventory.",
		Write: writeTextExport,
	})
}

// ReadCSVTable reads a CSV with a header row. It strips a UTF-8 BOM, accepts
// ragged rows and lowercases header names.
func ReadCSVTable(data []byte) ([]string, [][]string, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return nil, nil, transferErr(TransferInvalid, "The CSV is not UTF-8 text.")
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, nil, transferErr(TransferInvalid, "The CSV could not be read: %v", err)
	}
	if len(rows) == 0 {
		return nil, nil, transferErr(TransferEmpty, "The CSV is empty.")
	}
	head := make([]string, len(rows[0]))
	for i, h := range rows[0] {
		head[i] = strings.ToLower(strings.TrimSpace(h))
	}
	body := [][]string{}
	for _, row := range rows[1:] {
		blank := true
		for _, c := range row {
			if strings.TrimSpace(c) != "" {
				blank = false
				break
			}
		}
		if !blank {
			body = append(body, row)
		}
	}
	return head, body, nil
}

// CSVColumns maps header names to indexes for quick lookups.
type CSVColumns map[string]int

func NewCSVColumns(head []string) CSVColumns {
	c := CSVColumns{}
	for i, h := range head {
		if _, ok := c[h]; !ok {
			c[h] = i
		}
	}
	return c
}

func (c CSVColumns) Has(names ...string) bool {
	for _, n := range names {
		if _, ok := c[n]; !ok {
			return false
		}
	}
	return true
}

// Get returns the first non-empty cell among the named columns.
func (c CSVColumns) Get(row []string, names ...string) string {
	for _, n := range names {
		if i, ok := c[n]; ok && i < len(row) {
			if v := strings.TrimSpace(row[i]); v != "" {
				return v
			}
		}
	}
	return ""
}

func csvHead(data []byte) []string {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	line := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		line = data[:i]
	}
	r := csv.NewReader(bytes.NewReader(line))
	r.LazyQuotes = true
	rec, err := r.Read()
	if err != nil {
		return nil
	}
	for i := range rec {
		rec[i] = strings.ToLower(strings.TrimSpace(rec[i]))
	}
	return rec
}

func detectGenericCSV(name string, data []byte) int {
	head := csvHead(data)
	cols := NewCSVColumns(head)
	score := 0
	if strings.EqualFold(filepath.Ext(name), ".csv") {
		score = 10
	}
	if cols.Has("password") || cols.Has("username/secret") || cols.Has("secret") || cols.Has("otpauth") || cols.Has("totp") {
		score += 30
	}
	if cols.Has("url") || cols.Has("website") || cols.Has("login_uri") {
		score += 10
	}
	if score < 30 {
		return 0
	}
	return score
}

func parseGenericCSV(name string, data []byte, password string) (*TransferSet, error) {
	head, rows, err := ReadCSVTable(data)
	if err != nil {
		return nil, err
	}
	c := NewCSVColumns(head)
	set := &TransferSet{Format: "csv", FormatLabel: "CSV", Vendor: "generic"}
	switch {
	case c.Has("httprealm", "formactionorigin"):
		set.Format, set.FormatLabel = "firefox-csv", "Firefox passwords CSV"
	case c.Has("otpauth") && c.Has("title", "url"):
		set.Format, set.FormatLabel = "safari-csv", "Safari passwords CSV"
	case c.Has("name", "url", "username", "password") && len(head) <= 5:
		set.Format, set.FormatLabel = "chrome-csv", "Chrome, Edge or Brave passwords CSV"
	case c.Has("type", "account", "username/secret"):
		set.Format, set.FormatLabel = "apm-csv", "APM CSV (version 1)"
	case c.Has("type", "space", "name"):
		set.Format, set.FormatLabel = "apm-csv", "APM CSV"
	}
	for _, row := range rows {
		typ := strings.ToLower(c.Get(row, "type"))
		switch typ {
		case "entry", "login", "password":
			typ = "password"
		case "api_key":
			typ = "apikey"
		case "recovery":
			typ = "recovery"
		case "ssh_key", "sshkey":
			typ = "ssh_key"
		}
		if typ == "" {
			typ = "password"
		}
		spec, ok := ItemTypeByID(typ)
		if !ok {
			if s, ok2 := ItemTypeByCategory(typ); ok2 {
				spec, ok = s, true
				typ = s.ID
			}
		}
		title := c.Get(row, "name", "title", "account", "label", "service")
		url := c.Get(row, "url", "website", "login_uri", "uri", "hostname", "origin")
		user := c.Get(row, "username", "login", "user", "email", "login_username")
		pass := c.Get(row, "password", "login_password", "pass")
		note := c.Get(row, "note", "notes", "comment", "extra")
		otp := c.Get(row, "otpauth", "totp", "otp", "login_totp")
		if set.Format == "apm-csv" && c.Has("username/secret") {
			user = c.Get(row, "username/secret")
		}
		if !ok {
			it := NewTransferItem("note", title)
			it.Problem("APM has no %q item type", typ)
			set.Add(it)
			continue
		}
		it := NewTransferItem(typ, title)
		if s := c.Get(row, "space"); s != "" {
			it.Space, it.HasSpace = s, true
		}
		switch typ {
		case "password":
			it.Set("username", user)
			it.Set("password", pass)
			it.Set("website", url)
			it.Note("", note)
			if extra := c.Get(row, "urls"); extra != "" {
				it.Set("urls", toStringList(extra))
			}
			idx := set.Add(it)
			if otp != "" {
				set.AddTOTP(idx, otp)
			}
			continue
		case "totp":
			secret := otp
			if secret == "" {
				secret = firstNonEmpty(user, pass)
			}
			s, problem := TOTPSecretFrom(secret)
			it.Set("secret", s)
			it.Set("domain", normalizeDomain(url))
			if problem != "" {
				it.Problem("%s", problem)
			}
		default:
			secret := firstNonEmpty(pass, user)
			if set.Format == "apm-csv" && c.Has("username/secret") && typ == "apikey" {
				it.Set("service", user)
				secret = pass
			}
			if spec.Secret != "" && secret != "" {
				if spec.Secret == "codes" {
					it.Set("codes", toStringList(secret))
				} else {
					it.Set(spec.Secret, secret)
				}
			}
			it.Note("", note)
		}
		set.Add(it)
	}
	return set, nil
}

func firstNonEmpty(list ...string) string {
	for _, s := range list {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func detectText(name string, data []byte) int {
	if !utf8.Valid(data) {
		return 0
	}
	s := string(data)
	switch {
	case strings.HasPrefix(strings.TrimSpace(s), "APM Export"):
		return 70
	case strings.Contains(s, "otpauth://"):
		if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
			return 5
		}
		return 50
	case strings.EqualFold(filepath.Ext(name), ".txt"):
		return 5
	}
	return 0
}

func parseText(name string, data []byte, password string) (*TransferSet, error) {
	set := &TransferSet{Format: "txt", FormatLabel: "Text with otpauth:// links", Vendor: "generic"}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if strings.HasPrefix(strings.TrimSpace(string(data)), "APM Export") {
		set.Format, set.FormatLabel, set.Vendor = "apm-txt", "APM text export", "apm"
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.Index(line, "otpauth://"); i >= 0 {
			uri := strings.Fields(line[i:])[0]
			o, err := ParseOTPAuth(uri)
			it := NewTransferItem("totp", o.Name())
			if err != nil {
				it.Problem("The otpauth:// link is not valid")
			} else {
				s, problem := TOTPSecretFrom(uri)
				it.Set("secret", s)
				if problem != "" {
					it.Problem("%s", problem)
				}
			}
			set.Add(it)
			continue
		}
		if !strings.Contains(line, "|") {
			continue
		}
		parts := map[string]string{}
		for _, p := range strings.Split(line, "|") {
			if k, val, ok := strings.Cut(p, ":"); ok {
				parts[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(val)
			}
		}
		switch {
		case parts["account"] != "" && parts["password"] != "":
			it := NewTransferItem("password", parts["account"])
			it.Set("username", parts["username"])
			it.Set("password", parts["password"])
			set.Add(it)
		case parts["account"] != "" && parts["secret"] != "":
			it := NewTransferItem("totp", parts["account"])
			s, problem := TOTPSecretFrom(parts["secret"])
			it.Set("secret", s)
			if problem != "" {
				it.Problem("%s", problem)
			}
			set.Add(it)
		case parts["ssid"] != "" && parts["password"] != "":
			it := NewTransferItem("wifi", parts["ssid"])
			it.Set("password", parts["password"])
			it.Set("security_type", parts["security"])
			set.Add(it)
		case parts["name"] != "" && parts["token"] != "":
			it := NewTransferItem("token", parts["name"])
			it.Set("token", parts["token"])
			set.Add(it)
		case parts["name"] != "" && parts["key"] != "":
			it := NewTransferItem("apikey", parts["name"])
			it.Set("service", parts["service"])
			it.Set("key", parts["key"])
			set.Add(it)
		case parts["service"] != "" && parts["codes"] != "":
			it := NewTransferItem("recovery", parts["service"])
			it.Set("codes", toStringList(parts["codes"]))
			set.Add(it)
		}
	}
	return set, nil
}

func primarySecret(it *TransferItem) string {
	spec, ok := ItemTypeByID(it.Type)
	if !ok || spec.Secret == "" {
		return ""
	}
	return secretValue(it.Fields, spec.Secret)
}

// otherFields lists the fields that have no CSV column, as "Label: value".
func otherFields(it *TransferItem, skip ...string) string {
	spec, _ := ItemTypeByID(it.Type)
	keys := []string{}
	for k := range it.Fields {
		if k == spec.TitleKey || k == spec.Secret || containsString(skip, k) || fieldText(it.Fields[k]) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fieldOrder(it.Type, keys[i]) < fieldOrder(it.Type, keys[j]) })
	lines := []string{}
	for _, k := range keys {
		lines = append(lines, FieldLabel(it.Type, k)+": "+fieldText(it.Fields[k]))
	}
	return strings.Join(lines, "\n")
}

func writeCSVExport(items []TransferItem, opt ExportOptions) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"name", "url", "username", "password", "note", "totp", "type", "space"})
	for i := range items {
		it := &items[i]
		url, user, secret, note, totp := "", "", "", "", ""
		switch it.Type {
		case "password":
			url, user, secret = it.Get("website"), it.Get("username"), it.Get("password")
			note = joinNotes(it.Get("notes"), otherFields(it, "website", "username", "notes"))
		case "totp":
			url = it.Get("domain")
			if s := it.Get("secret"); s != "" {
				totp = fmt.Sprintf("otpauth://totp/%s?secret=%s", urlPathEscape(it.Title), s)
			}
		default:
			user = firstNonEmpty(it.Get("username"), it.Get("user"), it.Get("service"))
			secret = primarySecret(it)
			note = otherFields(it, "username", "user", "service")
		}
		if !opt.Secrets {
			secret, totp = "", ""
		}
		_ = w.Write([]string{it.Title, url, user, secret, note, totp, it.Type, it.Space})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func urlPathEscape(s string) string {
	return strings.NewReplacer("%", "%25", " ", "%20", "/", "%2F", "?", "%3F", "#", "%23", ":", "%3A").Replace(s)
}

func writeTextExport(items []TransferItem, opt ExportOptions) ([]byte, error) {
	var b strings.Builder
	b.WriteString("APM Export\n==========\n")
	byType := map[string][]*TransferItem{}
	order := []string{}
	for i := range items {
		it := &items[i]
		if _, ok := byType[it.Type]; !ok {
			order = append(order, it.Type)
		}
		byType[it.Type] = append(byType[it.Type], it)
	}
	for _, t := range order {
		b.WriteString("\n" + strings.ToUpper(typePlural(t)) + ":\n")
		for _, it := range byType[t] {
			line := []string{"Name: " + it.Title}
			if it.Space != "" {
				line = append(line, "Space: "+it.Space)
			}
			switch it.Type {
			case "password":
				line[0] = "Account: " + it.Title
				line = append(line, "Username: "+it.Get("username"))
				if w := it.Get("website"); w != "" {
					line = append(line, "Website: "+w)
				}
				if opt.Secrets {
					line = append(line, "Password: "+it.Get("password"))
				}
				if n := len(it.Passkeys); n > 0 {
					line = append(line, fmt.Sprintf("Passkeys: %d", n))
				}
			case "totp":
				line[0] = "Account: " + it.Title
				if opt.Secrets {
					line = append(line, "Secret: "+it.Get("secret"))
				}
			default:
				if opt.Secrets {
					if s := primarySecret(it); s != "" {
						spec, _ := ItemTypeByID(it.Type)
						s = strings.ReplaceAll(s, "\n", " ")
						line = append(line, FieldLabel(it.Type, spec.Secret)+": "+s)
					}
				}
			}
			b.WriteString(strings.Join(line, " | ") + "\n")
		}
	}
	return []byte(b.String()), nil
}
