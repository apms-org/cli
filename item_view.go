package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aaravmaloo/apm/internal/tty"
	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
)

// itemField is one field of an item type. The table below mirrors the desktop
// app's types (GUI renderer/src/lib/types.js), so pm get labels, orders and
// masks every field the way the app does.
type itemField struct {
	Key      string
	Label    string
	Kind     string
	Required bool
	Options  []string
}

type itemKind struct {
	Label  string
	Fields []itemField
}

func fld(key, label, kind string) itemField { return itemField{Key: key, Label: label, Kind: kind} }

func req(key, label, kind string) itemField {
	return itemField{Key: key, Label: label, Kind: kind, Required: true}
}

func sel(key, label string, options ...string) itemField {
	return itemField{Key: key, Label: label, Kind: "select", Options: options}
}

var itemKinds = map[string]itemKind{
	"password":    {"Login", []itemField{req("account", "Name", "text"), fld("username", "Username", "text"), req("password", "Password", "password"), fld("totp", "Two-factor code", "totp"), fld("website", "Website", "text"), fld("urls", "Other websites", "list"), fld("notes", "Notes", "multiline"), fld("fields", "Custom fields", "custom")}},
	"totp":        {"Authenticator", []itemField{req("account", "Name", "text"), req("secret", "Setup key", "totp"), fld("domain", "Website", "text")}},
	"note":        {"Secure note", []itemField{req("name", "Title", "text"), fld("content", "Note", "multiline")}},
	"wifi":        {"Wi-Fi network", []itemField{req("ssid", "Network name", "text"), req("password", "Password", "password"), sel("security_type", "Security", "WPA3 Personal", "WPA2 Personal", "WPA2 Enterprise", "WEP", "Open"), fld("router_ip", "Router address", "text")}},
	"govid":       {"Government ID", []itemField{req("name", "Name", "text"), sel("type", "Document", "Passport", "Driver's License", "Voter ID", "National ID"), req("id_number", "ID number", "secret"), fld("expiry", "Expires", "date")}},
	"medical":     {"Medical record", []itemField{req("label", "Name", "text"), fld("insurance_id", "Insurance ID", "text"), fld("prescriptions", "Prescriptions", "multiline"), fld("allergies", "Allergies", "text")}},
	"travel":      {"Travel", []itemField{req("label", "Name", "text"), fld("ticket_number", "Ticket number", "text"), fld("booking_code", "Booking code", "secret"), fld("loyalty_program", "Loyalty program", "text")}},
	"contact":     {"Contact", []itemField{req("name", "Name", "text"), fld("phone", "Phone", "text"), fld("email", "Email", "text"), fld("address", "Address", "multiline"), fld("emergency", "Emergency contact", "bool")}},
	"recovery":    {"Recovery codes", []itemField{req("service", "Service", "text"), req("codes", "Codes", "codes")}},
	"apikey":      {"API key", []itemField{req("name", "Name", "text"), fld("service", "Service", "text"), req("key", "Key", "secret")}},
	"token":       {"Token", []itemField{req("name", "Name", "text"), req("token", "Token", "secret"), fld("type", "Kind", "text")}},
	"ssh_key":     {"SSH key", []itemField{req("name", "Name", "text"), req("private_key", "Private key", "secretBlock")}},
	"ssh_config":  {"SSH host", []itemField{req("alias", "Alias", "text"), req("host", "Host", "text"), fld("user", "User", "text"), fld("port", "Port", "text"), fld("key_path", "Key path", "text"), fld("private_key", "Private key", "secretBlock"), fld("fingerprint", "Fingerprint", "text")}},
	"cloud":       {"Cloud credentials", []itemField{req("label", "Name", "text"), fld("access_key", "Access key", "secret"), fld("secret_key", "Secret key", "secret"), fld("region", "Region", "text"), fld("account_id", "Account ID", "text"), fld("role", "Role", "text"), fld("expiration", "Expires", "date")}},
	"k8s":         {"Kubernetes", []itemField{req("name", "Name", "text"), fld("cluster_url", "Cluster URL", "text"), fld("namespace", "Namespace", "text"), fld("expiration", "Expires", "date")}},
	"docker":      {"Docker registry", []itemField{req("name", "Name", "text"), fld("registry_url", "Registry", "text"), fld("username", "Username", "text"), fld("token", "Token", "secret")}},
	"cicd":        {"CI/CD secret", []itemField{req("name", "Name", "text"), fld("webhook", "Webhook", "secret"), fld("env_vars", "Environment variables", "multiline")}},
	"certificate": {"Certificate", []itemField{req("label", "Name", "text"), fld("issuer", "Issuer", "text"), fld("expiry", "Expires", "date"), fld("cert_data", "Certificate", "secretBlock"), fld("private_key", "Private key", "secretBlock")}},
	"banking":     {"Card or account", []itemField{req("label", "Name", "text"), sel("type", "Kind", "Card", "IBAN", "SWIFT"), req("details", "Number", "secret"), fld("cvv", "CVV", "secret"), fld("expiry", "Expires", "text")}},
	"license":     {"Software license", []itemField{req("product_name", "Product", "text"), req("serial_key", "Serial key", "secret"), fld("activation_info", "Activation", "text"), fld("expiration", "Expires", "date")}},
	"legal":       {"Legal contract", []itemField{req("name", "Name", "text"), fld("summary", "Summary", "multiline"), fld("parties_involved", "Parties", "text"), fld("signed_date", "Signed", "date")}},
	"document":    {"Document", []itemField{req("name", "Name", "text"), req("file", "File", "file"), fld("password", "Document password", "password"), fld("tags", "Tags", "list"), fld("expiry", "Expires", "date")}},
	"photo":       {"Photo", []itemField{req("name", "Name", "text"), req("file", "Image", "file")}},
	"audio":       {"Audio", []itemField{req("name", "Name", "text"), req("file", "Audio file", "file")}},
	"video":       {"Video", []itemField{req("name", "Name", "text"), req("file", "Video file", "file")}},
}

func kindOf(ref src.VaultItemRef) itemKind {
	if k, ok := itemKinds[ref.Spec.ID]; ok {
		return k
	}
	return itemKind{Label: ref.Spec.ID, Fields: []itemField{req(ref.Spec.TitleKey, "Name", "text")}}
}

func isSecretKind(kind string) bool {
	switch kind {
	case "password", "secret", "secretBlock", "codes":
		return true
	}
	return false
}

func itemTitle(ref src.VaultItemRef) string {
	if strings.TrimSpace(ref.Title) != "" {
		return ref.Title
	}
	return kindOf(ref).Label
}

// itemLookup ties search results back to the vault items behind them and
// answers the questions a login's bundle raises: which Authenticator code it
// uses, and which logins use an Authenticator code.
type itemLookup struct {
	v        *src.Vault
	ix       *bridgeIndex
	byResult map[string]src.VaultItemRef
}

func newItemLookup(v *src.Vault) *itemLookup {
	l := &itemLookup{v: v, ix: newBridgeIndex(v), byResult: map[string]src.VaultItemRef{}}
	for _, r := range l.ix.refs {
		// SearchAll names an item by its title, except government IDs, which it
		// names by ID number, the same field their telemetry uses.
		ident := r.Title
		if r.Spec.TelemetryField != "" {
			ident = v.ItemElem(r).FieldByName(r.Spec.TelemetryField).String()
		}
		l.byResult[resultKey(r.Spec.Category, r.Space, ident)] = r
	}
	return l
}

func resultKey(category, space, ident string) string {
	return category + "\x00" + strings.ToLower(space) + "\x00" + ident
}

func (l *itemLookup) ref(res src.SearchResult) (src.VaultItemRef, bool) {
	r, ok := l.byResult[resultKey(resultTypeToHistoryCategory(res.Type), res.Space, res.Identifier)]
	return r, ok
}

func refForResult(v *src.Vault, res src.SearchResult) (src.VaultItemRef, bool) {
	return newItemLookup(v).ref(res)
}

// loginCode is the Authenticator item a login without its own key borrows
// its one-time code from.
func (l *itemLookup) loginCode(login src.VaultItemRef) (src.VaultItemRef, string, bool) {
	t, ok := l.ix.linkedTOTP(login)
	if !ok || t.Spec.ID != "totp" {
		return src.VaultItemRef{}, "", false
	}
	return t, toStr(l.ix.fields[t.ID]["secret"]), true
}

// codeUsers lists the logins that take their one-time code from an
// Authenticator item.
func (l *itemLookup) codeUsers(totp src.VaultItemRef) []string {
	var out []string
	for _, r := range l.ix.refs {
		if r.Spec.ID != "password" {
			continue
		}
		if t, ok := l.ix.linkedTOTP(r); ok && t.ID == totp.ID {
			out = append(out, itemTitle(r))
		}
	}
	return out
}

func (l *itemLookup) hasCode(ref src.VaultItemRef) bool {
	switch ref.Spec.ID {
	case "totp":
		return true
	case "password":
		_, ok := l.ix.linkedTOTP(ref)
		return ok
	}
	return false
}

// searchTerms are the parts of an item besides its name that pm get matches:
// a login's username, sites and passkey sites, and an Authenticator's sites.
func (l *itemLookup) searchTerms(ref src.VaultItemRef) []string {
	switch ref.Spec.ID {
	case "password":
		e := l.v.Entries[ref.Index]
		out := []string{e.Username, bridgeHost(e.Website)}
		for _, u := range e.URLs {
			out = append(out, bridgeHost(u))
		}
		for _, pk := range e.Passkeys {
			out = append(out, pk.RPID)
		}
		return out
	case "totp":
		return totpDomainsFor(l.v, ref.Title)
	}
	return nil
}

func fileSummary(file map[string]any) string {
	name := toStr(file["name"])
	if name == "" {
		return ""
	}
	size, _ := file["size"].(int)
	return name + " · " + humanSize(size)
}

func humanSize(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%d KB", n/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

func liveCode(secret string) string {
	code, err := src.GenerateTOTP(secret)
	if err != nil {
		return color.RedString("invalid setup key")
	}
	return color.New(color.Bold).Sprint(code) + color.New(color.Faint).Sprintf("  %ds left", src.TimeRemaining())
}

func passkeyDate(s *string) string {
	n := parseJSTime(s)
	if n == 0 {
		return ""
	}
	return time.UnixMilli(n).Local().Format("2006-01-02")
}

func passkeyLine(pk src.Passkey) string {
	parts := []string{pk.RPID}
	if u := firstNonEmpty(pk.UserName, pk.UserDisplayName); u != "" {
		parts = append(parts, u)
	}
	if pk.Label != "" {
		parts = append(parts, fmt.Sprintf("%q", pk.Label))
	}
	created := pk.CreatedAt
	if d := passkeyDate(&created); d != "" {
		parts = append(parts, "added "+d)
	}
	if d := passkeyDate(pk.LastUsedAt); d != "" {
		parts = append(parts, "last used "+d)
	} else {
		parts = append(parts, "never used")
	}
	return strings.Join(parts, " · ")
}

type copyTarget struct {
	label  string
	secret bool
	value  func() string
}

type cardRow struct {
	label string
	value string
}

// itemCard renders one item: its name, what it is, its filled fields in the
// desktop app's order and, for a login, everything bundled into it: the
// one-time code (its own or a linked Authenticator's) and its passkeys.
// Secrets stay masked unless reveal is set. It also returns what can be
// copied, with the main secret first.
func itemCard(l *itemLookup, ref src.VaultItemRef, reveal bool) ([]string, []copyTarget) {
	k := kindOf(ref)
	f := l.ix.fields[ref.ID]
	var rows []cardRow
	var copies []copyTarget
	add := func(label, value string) { rows = append(rows, cardRow{label, value}) }
	copyable := func(label, value string, secret bool) {
		if value == "" {
			return
		}
		t := copyTarget{label: label, secret: secret, value: func() string { return value }}
		if secret && len(copies) > 0 && !copies[0].secret {
			copies = append([]copyTarget{t}, copies...)
			return
		}
		copies = append(copies, t)
	}
	masked := func(value string) string {
		if reveal {
			return value
		}
		return "********"
	}
	code := func(secret, from string) {
		value := liveCode(secret)
		if from != "" {
			value += color.New(color.Faint).Sprintf("  from Authenticator %q", from)
		}
		add("One-time code", value)
		copies = append(copies, copyTarget{label: "One-time code", secret: true, value: func() string {
			c, _ := src.GenerateTOTP(secret)
			return c
		}})
	}

	for _, fd := range k.Fields {
		if fd.Key == ref.Spec.TitleKey {
			continue
		}
		raw := f[fd.Key]
		switch fd.Kind {
		case "totp":
			secret := strings.TrimSpace(toStr(raw))
			if secret == "" {
				if ref.Spec.ID == "password" {
					if t, s, ok := l.loginCode(ref); ok {
						code(s, itemTitle(t))
					}
				}
				continue
			}
			code(secret, "")
			if reveal {
				add("Setup key", secret)
			}
		case "custom":
			for _, cf := range toCustomFieldList(raw) {
				label := firstNonEmpty(cf.Label, "Field")
				if cf.Hidden {
					add(label, masked(cf.Value))
				} else {
					add(label, cf.Value)
				}
				copyable(label, cf.Value, cf.Hidden)
			}
		case "file":
			if file, ok := raw.(map[string]any); ok {
				if s := fileSummary(file); s != "" {
					add(fd.Label, s)
				}
			}
		case "bool":
			if b, _ := raw.(bool); b {
				add(fd.Label, "Yes")
			}
		case "list", "codes":
			list, _ := raw.([]string)
			if len(list) == 0 {
				continue
			}
			if fd.Kind == "codes" {
				add(fd.Label, masked(strings.Join(list, "\n"))+color.New(color.Faint).Sprintf("  %s", plural(len(list), "code")))
				copyable(fd.Label, strings.Join(list, "\n"), true)
				continue
			}
			add(fd.Label, strings.Join(list, ", "))
		default:
			s := toStr(raw)
			if ref.Spec.ID == "totp" && fd.Key == "domain" {
				s = strings.Join(totpDomainsFor(l.v, ref.Title), ", ")
			}
			if strings.TrimSpace(s) == "" {
				continue
			}
			if !isSecretKind(fd.Kind) {
				add(fd.Label, s)
				if fd.Key == "username" || fd.Key == "user" {
					copyable(fd.Label, s, false)
				}
				continue
			}
			shown := masked(s)
			if !reveal && ref.Spec.ID == "banking" && fd.Key == "details" {
				if d := strings.ReplaceAll(s, " ", ""); len(d) > 4 {
					shown += color.New(color.Faint).Sprintf("  ending %s", d[len(d)-4:])
				}
			}
			add(fd.Label, shown)
			copyable(fd.Label, s, true)
		}
	}
	if ref.Spec.ID == "totp" {
		if users := l.codeUsers(ref); len(users) > 0 {
			add("Used by", strings.Join(users, ", "))
		}
	}

	var passkeys []src.Passkey
	if ref.Spec.ID == "password" {
		passkeys = l.v.Entries[ref.Index].Passkeys
	}
	meta := []string{k.Label, "space: " + spaceOrDefaultName(ref.Space)}
	if l.hasCode(ref) && ref.Spec.ID == "password" {
		meta = append(meta, "2FA on")
	}
	if len(passkeys) > 0 {
		meta = append(meta, plural(len(passkeys), "passkey"))
	}
	lines := []string{color.New(color.Bold).Sprint(itemTitle(ref)), color.New(color.Faint).Sprint(strings.Join(meta, " · ")), ""}
	lines = append(lines, alignRows(rows, "  ")...)
	if len(rows) == 0 {
		lines = append(lines, color.New(color.Faint).Sprint("  No details yet."))
	}
	if len(passkeys) > 0 {
		lines = append(lines, "", "  "+color.New(color.Bold).Sprint("Passkeys"))
		for _, pk := range passkeys {
			lines = append(lines, "    "+passkeyLine(pk))
		}
	}
	return lines, copies
}

// alignRows lays rows out as a label column and a value column. A value with
// several lines continues under its first line.
func alignRows(rows []cardRow, indent string) []string {
	w := 0
	for _, r := range rows {
		if n := utf8.RuneCountInString(r.label); n > w {
			w = n
		}
	}
	var out []string
	for _, r := range rows {
		pad := strings.Repeat(" ", w-utf8.RuneCountInString(r.label)+3)
		for i, line := range strings.Split(r.value, "\n") {
			if i == 0 {
				out = append(out, indent+color.New(color.Faint).Sprint(r.label)+pad+line)
			} else {
				out = append(out, indent+strings.Repeat(" ", w+3)+line)
			}
		}
	}
	return out
}

func toCustomFieldList(raw any) []src.CustomField {
	var out []src.CustomField
	switch t := raw.(type) {
	case []src.CustomField:
		return t
	case []map[string]any:
		for _, m := range t {
			hidden, _ := m["hidden"].(bool)
			out = append(out, src.CustomField{Label: toStr(m["label"]), Value: toStr(m["value"]), Hidden: hidden})
		}
	}
	return out
}

// copyMenu offers everything on a card that can be copied, one number each,
// and opening the item's file when open is set, until the user presses Enter.
func copyMenu(copies []copyTarget, open func()) {
	opts := []string{}
	for i, c := range copies {
		opts = append(opts, fmt.Sprintf("[%d] %s", i+1, c.label))
	}
	line := ""
	if len(opts) > 0 {
		line = "Copy " + strings.Join(opts, "  ") + "  ·  "
	}
	if open != nil {
		line += "[o] Open file  ·  "
	}
	for {
		// Esc goes back too; it does not end the command.
		in, err := readLineOpts(tty.LineOptions{Prompt: "\n" + line + "Enter to go back: "})
		in = strings.ToLower(strings.TrimSpace(in))
		if err != nil || in == "" {
			return
		}
		if in == "o" && open != nil {
			open()
			continue
		}
		var n int
		if _, err := fmt.Sscanf(in, "%d", &n); err == nil && n >= 1 && n <= len(copies) {
			c := copies[n-1]
			if c.secret {
				copyToClipboardWithExpiry(c.value())
			} else {
				copyToClipboard(c.value())
				color.Green("Copied %s.", strings.ToLower(c.label))
			}
			continue
		}
		color.Yellow("Pick one of the options, or press Enter.")
	}
}

func sortedSpaces(v *src.Vault, current string) []string {
	seen := map[string]bool{"default": true}
	out := []string{}
	for _, s := range append(append([]string{}, v.Spaces...), current) {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return append([]string{"default"}, out...)
}

// resultLine is a search result as pm get lists it: name and kind.
func resultLine(look *itemLookup, r src.SearchResult) string {
	name, kind := r.Identifier, r.Type
	if ref, ok := look.ref(r); ok {
		name, kind = itemTitle(ref), kindOf(ref).Label
	}
	return fmt.Sprintf("%-28s %s", clipRunes(name, 28), kind)
}

// deleteWarning says what else goes when a login is deleted.
func deleteWarning(look *itemLookup, ref src.VaultItemRef) string {
	if ref.Spec.ID != "password" {
		return ""
	}
	e := look.v.Entries[ref.Index]
	var parts []string
	if strings.TrimSpace(e.TOTP) != "" {
		parts = append(parts, "its 2FA key")
	}
	if n := len(e.Passkeys); n > 0 {
		parts = append(parts, plural(n, "passkey"))
	}
	if len(parts) == 0 {
		return ""
	}
	return "This also deletes " + strings.Join(parts, " and ") + ". "
}

// resultIndex is a row's number, padded so [9] and [10] start their names in
// the same column.
func resultIndex(i, total int) string {
	return fmt.Sprintf("%-*s", len(fmt.Sprintf("[%d]", total)), fmt.Sprintf("[%d]", i+1))
}
