package apm

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	RowNew       = "new"
	RowIdentical = "identical"
	RowConflict  = "conflict"
	RowDuplicate = "duplicate"
	RowInvalid   = "invalid"

	ActionAdd     = "add"
	ActionSkip    = "skip"
	ActionMerge   = "merge"
	ActionReplace = "replace"
)

type FieldChange struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Current  string `json:"current"`
	Incoming string `json:"incoming"`
	Secret   bool   `json:"secret"`
	Kind     string `json:"kind"`
}

type TransferMatch struct {
	ID    string `json:"id,omitempty"`
	Row   int    `json:"row"`
	Type  string `json:"type"`
	Title string `json:"title"`
	Space string `json:"space"`
}

type TransferRow struct {
	Index       int              `json:"index"`
	Type        string           `json:"type"`
	Title       string           `json:"title"`
	Subtitle    string           `json:"subtitle"`
	Space       string           `json:"space"`
	Folder      string           `json:"folder"`
	Status      string           `json:"status"`
	Reason      string           `json:"reason"`
	Match       *TransferMatch   `json:"match,omitempty"`
	Changes     []FieldChange    `json:"changes"`
	Fields      map[string]any   `json:"fields,omitempty"`
	Passkeys    []PasskeySummary `json:"passkeys"`
	NewPasskeys int              `json:"newPasskeys"`
	Dropped     []DroppedPasskey `json:"dropped"`
	Warnings    []string         `json:"warnings"`
	Problems    []string         `json:"problems"`
	Default     string           `json:"default"`
	Actions     []string         `json:"actions"`
	Link        int              `json:"link"`
	Favorite    bool             `json:"favorite"`
	File        *FileSummary     `json:"file,omitempty"`
}

type PasskeySummary struct {
	RPID         string `json:"rpId"`
	UserName     string `json:"userName"`
	CredentialID string `json:"credentialId"`
	InVault      bool   `json:"inVault"`
}

type FileSummary struct {
	Name string `json:"name"`
	Size int    `json:"size"`
}

type PlanOptions struct {
	Space      string `json:"space"`
	KeepSpaces bool   `json:"keepSpaces"`
}

type PlanSummary struct {
	Total           int            `json:"total"`
	New             int            `json:"new"`
	Identical       int            `json:"identical"`
	Conflicts       int            `json:"conflicts"`
	Duplicates      int            `json:"duplicates"`
	Invalid         int            `json:"invalid"`
	Passkeys        int            `json:"passkeys"`
	NewPasskeys     int            `json:"newPasskeys"`
	DroppedPasskeys int            `json:"droppedPasskeys"`
	ByType          map[string]int `json:"byType"`
	Spaces          []string       `json:"spaces"`
}

type TransferPlan struct {
	Set     *TransferSet  `json:"-"`
	Options PlanOptions   `json:"options"`
	Rows    []TransferRow `json:"rows"`
	Summary PlanSummary   `json:"summary"`
}

type VaultOnlyItem struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	Space    string `json:"space"`
	Subtitle string `json:"subtitle"`
}

// planIndex is the vault as the planner sees it: items by name, logins by
// site and username, and secrets and passkeys by value.
type planIndex struct {
	v        *Vault
	byKey    map[string]planEntry
	byLogin  map[string]planEntry
	bySecret map[string]planEntry
	byCred   map[string]planEntry
}

type planEntry struct {
	id     string
	row    int
	typ    string
	title  string
	space  string
	fields map[string]any
	creds  map[string]bool
	file   string
	// inLogin marks the 2FA code held inside a login. It matches incoming
	// Authenticator items but cannot be merged or replaced in place.
	inLogin bool
}

func fileSum(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func itemKey(typ, space, title string) string {
	return typ + "\x00" + spaceKey(space) + "\x00" + strings.ToLower(strings.TrimSpace(title))
}

func loginHosts(f map[string]any) []string {
	hosts := []string{}
	add := func(u string) {
		if h := normalizeDomain(u); h != "" && !containsString(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	add(fieldText(f["website"]))
	for _, u := range toStringList(f["urls"]) {
		add(u)
	}
	return hosts
}

func secretFingerprint(typ string, f map[string]any) string {
	spec, ok := ItemTypeByID(typ)
	if !ok || spec.Secret == "" {
		return ""
	}
	val := secretValue(f, spec.Secret)
	if typ == "totp" {
		val = normalizeTOTPSecret(val)
	}
	val = strings.TrimSpace(val)
	if len(val) < 6 || typ == "password" || typ == "wifi" || typ == "note" {
		return ""
	}
	return typ + "\x00" + val
}

func newPlanIndex(v *Vault) *planIndex {
	ix := &planIndex{v: v, byKey: map[string]planEntry{}, byLogin: map[string]planEntry{}, bySecret: map[string]planEntry{}, byCred: map[string]planEntry{}}
	for _, ref := range v.ItemRefs() {
		f := v.ItemRecordFields(ref)
		e := planEntry{id: ref.ID, row: -1, typ: ref.Spec.ID, title: ref.Title, space: ref.Space, fields: f, creds: map[string]bool{}}
		for _, pk := range v.ItemPasskeys(ref) {
			e.creds[NormalizePasskeyCredentialID(pk.CredentialID)] = true
		}
		if _, data, ok := v.ItemFileContent(ref); ok {
			e.file = fileSum(data)
		}
		ix.put(e, nil)
		if secret := fieldText(f["totp"]); ref.Spec.ID == "password" && secret != "" {
			tf := map[string]any{"account": ref.Title, "secret": secret}
			if host := normalizeDomain(fieldText(f["website"])); host != "" {
				tf["domain"] = host
			}
			ix.put(planEntry{id: ref.ID, row: -1, typ: "totp", title: ref.Title, space: ref.Space, fields: tf, creds: map[string]bool{}, inLogin: true}, nil)
		}
	}
	return ix
}

func (ix *planIndex) put(e planEntry, passkeys []Passkey) {
	for _, pk := range passkeys {
		e.creds[NormalizePasskeyCredentialID(pk.CredentialID)] = true
	}
	k := itemKey(e.typ, e.space, e.title)
	if _, ok := ix.byKey[k]; !ok {
		ix.byKey[k] = e
	}
	if e.typ == "password" {
		if user := strings.ToLower(fieldText(e.fields["username"])); user != "" {
			for _, h := range loginHosts(e.fields) {
				if _, ok := ix.byLogin[h+"\x00"+user]; !ok {
					ix.byLogin[h+"\x00"+user] = e
				}
			}
		}
	}
	if fp := secretFingerprint(e.typ, e.fields); fp != "" {
		if _, ok := ix.bySecret[fp]; !ok {
			ix.bySecret[fp] = e
		}
	}
	for c := range e.creds {
		if _, ok := ix.byCred[c]; !ok {
			ix.byCred[c] = e
		}
	}
}

func (ix *planIndex) credInVault(c string) bool {
	e, ok := ix.byCred[c]
	return ok && e.row < 0
}

// similar finds an item that holds the same credential under another name.
func (ix *planIndex) similar(it *TransferItem) (planEntry, string, bool) {
	for _, pk := range it.Passkeys {
		if e, ok := ix.byCred[NormalizePasskeyCredentialID(pk.CredentialID)]; ok {
			return e, "the same passkey for " + pk.RPID, true
		}
	}
	if it.Type == "password" {
		if user := strings.ToLower(it.Get("username")); user != "" {
			for _, h := range loginHosts(it.Fields) {
				if e, ok := ix.byLogin[h+"\x00"+user]; ok {
					return e, "the same username on " + h, true
				}
			}
		}
	}
	if fp := secretFingerprint(it.Type, it.Fields); fp != "" {
		if e, ok := ix.bySecret[fp]; ok {
			what := "the same secret"
			if spec, ok := ItemTypeByID(it.Type); ok {
				what = "the same " + strings.ToLower(FieldLabel(it.Type, spec.Secret))
			}
			return e, what, true
		}
	}
	return planEntry{}, "", false
}

func (p *TransferPlan) targetSpace(it *TransferItem) string {
	if p.Options.KeepSpaces {
		if it.HasSpace {
			return normalizeSpaceName(it.Space)
		}
		if f := strings.TrimSpace(it.Folder); f != "" {
			return normalizeSpaceName(f)
		}
	}
	return normalizeSpaceName(p.Options.Space)
}

func normalizeSpaceName(s string) string {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "default") {
		return ""
	}
	return s
}

func PlanTransfer(v *Vault, set *TransferSet, opt PlanOptions) *TransferPlan {
	p := &TransferPlan{Set: set, Options: opt}
	ix := newPlanIndex(v)
	spaces := map[string]bool{}
	for i := range set.Items {
		it := &set.Items[i]
		row := TransferRow{Index: i, Type: it.Type, Title: it.Title, Subtitle: transferSubtitle(it, set), Folder: it.Folder, Space: p.targetSpace(it), Link: it.Link, Favorite: it.Favorite,
			Changes: []FieldChange{}, Passkeys: []PasskeySummary{}, Dropped: append([]DroppedPasskey{}, it.Dropped...), Warnings: append([]string{}, it.Warnings...), Problems: append([]string{}, it.Problems...), Actions: []string{}}
		row.Fields = map[string]any{}
		for k, val := range it.Fields {
			row.Fields[k] = val
		}
		if it.File != nil {
			row.File = &FileSummary{Name: it.File.Name, Size: len(it.File.Data)}
		}
		for _, pk := range it.Passkeys {
			c := NormalizePasskeyCredentialID(pk.CredentialID)
			in := ix.credInVault(c)
			row.Passkeys = append(row.Passkeys, PasskeySummary{RPID: pk.RPID, UserName: pk.UserName, CredentialID: c, InVault: in})
			if !in {
				row.NewPasskeys++
			}
		}
		if len(row.Problems) > 0 {
			row.Status, row.Reason, row.Default = RowInvalid, row.Problems[0], ActionSkip
			p.Rows = append(p.Rows, row)
			continue
		}
		var match planEntry
		found, how := false, ""
		if e, ok := ix.byKey[itemKey(it.Type, row.Space, it.Title)]; ok {
			match, found, how = e, true, "name"
			if it.Type == "password" && differentAccounts(it.Fields, e.fields) {
				if alt, ok := ix.renamedCopy(it, row.Space); ok {
					match = alt
				} else if alt, why, ok := ix.similar(it); ok && !differentAccounts(it.Fields, alt.fields) {
					match, how = alt, why
				}
			}
		} else if e, why, ok := ix.similar(it); ok {
			match, found, how = e, true, why
		}
		if !found {
			row.Status, row.Default, row.Actions = RowNew, ActionAdd, []string{ActionAdd, ActionSkip}
		} else {
			row.Match = &TransferMatch{ID: match.id, Row: match.row, Type: match.typ, Title: match.title, Space: match.space}
			changes, additive := compareFields(it, match)
			row.Changes = changes
			newKeys := row.NewPasskeys
			if match.row >= 0 {
				newKeys = 0
				for _, pk := range it.Passkeys {
					if !match.creds[NormalizePasskeyCredentialID(pk.CredentialID)] {
						newKeys++
					}
				}
			}
			where := "in your vault"
			if match.row >= 0 {
				where = "earlier in this file"
			}
			switch {
			case len(changes) == 0 && newKeys == 0:
				row.Status = RowIdentical
				if how == "name" {
					row.Reason = "Already " + where
				} else {
					row.Reason = "Already " + where + " as " + quoteTitle(match.title, match.space)
				}
				row.Default, row.Actions = ActionSkip, []string{ActionSkip, ActionAdd}
			default:
				if how == "name" {
					row.Status = RowConflict
					row.Reason = "Same name " + where + ", " + describeChanges(changes, newKeys)
				} else {
					row.Status = RowDuplicate
					row.Reason = "Looks like " + quoteTitle(match.title, match.space) + " " + where + ": " + how
				}
				row.Actions = []string{ActionSkip, ActionMerge, ActionReplace, ActionAdd}
				switch {
				case how == "name" && it.Type == "password" && differentAccounts(it.Fields, match.fields):
					// Two logins with one name but different usernames are two
					// accounts on the same site, so keep both.
					row.Default = ActionAdd
					row.Reason = "Same name " + where + ", but a different username. Both are kept"
				case additive || newKeys > 0:
					// Merge never overwrites a value, so it is the safe way to
					// bring passkeys and missing fields along.
					row.Default = ActionMerge
				default:
					row.Default = ActionSkip
				}
				if match.inLogin {
					row.Reason = "Differs from the 2FA code inside " + quoteTitle(match.title, match.space)
					row.Default, row.Actions = ActionSkip, []string{ActionSkip, ActionAdd}
				}
			}
		}
		if row.Default != ActionSkip && row.Space != "" {
			spaces[row.Space] = true
		}
		p.Rows = append(p.Rows, row)
		e := planEntry{row: i, typ: it.Type, title: it.Title, space: row.Space, fields: it.Fields, creds: map[string]bool{}}
		if it.File != nil {
			e.file = fileSum(it.File.Data)
		}
		ix.put(e, it.Passkeys)
	}
	p.summarize(v, spaces)
	return p
}

func (p *TransferPlan) summarize(v *Vault, spaces map[string]bool) {
	s := PlanSummary{ByType: map[string]int{}, Spaces: []string{}}
	for _, r := range p.Rows {
		s.Total++
		s.ByType[r.Type]++
		s.Passkeys += len(r.Passkeys)
		s.NewPasskeys += r.NewPasskeys
		s.DroppedPasskeys += len(r.Dropped)
		switch r.Status {
		case RowNew:
			s.New++
		case RowIdentical:
			s.Identical++
		case RowConflict:
			s.Conflicts++
		case RowDuplicate:
			s.Duplicates++
		case RowInvalid:
			s.Invalid++
		}
	}
	for sp := range spaces {
		if !v.hasSpace(sp) {
			s.Spaces = append(s.Spaces, sp)
		}
	}
	sort.Strings(s.Spaces)
	p.Summary = s
}

func quoteTitle(title, space string) string {
	q := "“" + title + "”"
	if strings.TrimSpace(space) != "" {
		q += " in " + space
	}
	return q
}

func describeChanges(changes []FieldChange, newPasskeys int) string {
	parts := []string{}
	changed := []string{}
	added := []string{}
	for _, c := range changes {
		if c.Kind == "changed" {
			changed = append(changed, strings.ToLower(c.Label))
		} else {
			added = append(added, strings.ToLower(c.Label))
		}
	}
	if len(changed) > 0 {
		parts = append(parts, "different "+strings.Join(changed, ", "))
	}
	if len(added) > 0 {
		parts = append(parts, "adds "+strings.Join(added, ", "))
	}
	if newPasskeys > 0 {
		parts = append(parts, "adds "+plural(newPasskeys, "passkey"))
	}
	if len(parts) == 0 {
		return "no differences"
	}
	return strings.Join(parts, ", ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// compareFields lists what the incoming item would change. It reports whether
// every difference only fills a gap, so a merge loses nothing.
func compareFields(it *TransferItem, m planEntry) ([]FieldChange, bool) {
	spec, _ := ItemTypeByID(it.Type)
	keys := make([]string, 0, len(it.Fields))
	for k := range it.Fields {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fieldOrder(it.Type, keys[i]) < fieldOrder(it.Type, keys[j]) })
	out := []FieldChange{}
	additive := true
	for _, k := range keys {
		if k == spec.TitleKey && m.typ == it.Type {
			continue
		}
		inc := fieldText(it.Fields[k])
		if inc == "" {
			continue
		}
		cur := fieldText(m.fields[k])
		ch := FieldChange{Key: k, Label: FieldLabel(it.Type, k), Current: cur, Incoming: inc, Secret: isSecretField(it.Type, k)}
		switch k {
		case "urls":
			extra := []string{}
			have := map[string]bool{}
			for _, h := range loginHosts(m.fields) {
				have[h] = true
			}
			for _, u := range toStringList(it.Fields[k]) {
				if h := normalizeDomain(u); h != "" && !have[h] {
					extra = append(extra, u)
				}
			}
			if len(extra) == 0 {
				continue
			}
			ch.Kind, ch.Incoming = "added", strings.Join(extra, ", ")
		case "website":
			if cur == "" {
				ch.Kind = "added"
			} else if containsString(loginHosts(m.fields), normalizeDomain(inc)) {
				continue
			} else {
				ch.Kind, ch.Label = "added", "Other websites"
			}
		case "notes":
			if cur == "" {
				ch.Kind = "added"
			} else if strings.Contains(cur, strings.TrimSpace(inc)) {
				continue
			} else {
				ch.Kind = "added"
			}
		case "secret":
			if normalizeTOTPSecret(cur) == normalizeTOTPSecret(inc) {
				continue
			}
			if cur == "" {
				ch.Kind = "added"
			} else {
				ch.Kind = "changed"
			}
		case "codes", "tags", "used":
			if sameStringSet(toStringList(it.Fields[k]), toStringList(m.fields[k])) {
				continue
			}
			if cur == "" {
				ch.Kind = "added"
			} else {
				ch.Kind = "changed"
			}
		default:
			if cur == inc || (it.Type == "password" && k == "username" && strings.EqualFold(cur, inc)) {
				continue
			}
			if cur == "" {
				ch.Kind = "added"
			} else {
				ch.Kind = "changed"
			}
		}
		if ch.Kind == "changed" {
			additive = false
		}
		out = append(out, ch)
	}
	if it.File != nil && len(it.File.Data) > 0 && fileSum(it.File.Data) != m.file {
		kind := "changed"
		if m.file == "" {
			kind = "added"
		} else {
			additive = false
		}
		out = append(out, FieldChange{Key: "file", Label: "File", Incoming: it.File.Name, Kind: kind})
	}
	return out, additive
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[strings.TrimSpace(s)]++
	}
	for _, s := range b {
		m[strings.TrimSpace(s)]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

var fieldOrders = map[string][]string{
	"password": {"account", "username", "password", "website", "urls", "notes"},
	"totp":     {"account", "secret", "domain"},
}

func fieldOrder(typ, key string) int {
	for i, k := range fieldOrders[typ] {
		if k == key {
			return i
		}
	}
	return 100 + int(key[0])
}

var fieldLabels = map[string]string{
	"account": "Name", "username": "Username", "password": "Password", "website": "Website", "urls": "Other websites", "notes": "Notes",
	"secret": "Setup key", "domain": "Website", "content": "Note", "ssid": "Network name", "security_type": "Security", "router_ip": "Router address",
	"id_number": "ID number", "insurance_id": "Insurance ID", "booking_code": "Booking code", "ticket_number": "Ticket number", "loyalty_program": "Loyalty program",
	"codes": "Codes", "used": "Used codes", "key": "Key", "service": "Service", "token": "Token", "private_key": "Private key", "alias": "Alias", "host": "Host",
	"user": "User", "port": "Port", "key_path": "Key path", "fingerprint": "Fingerprint", "access_key": "Access key", "secret_key": "Secret key", "region": "Region",
	"account_id": "Account ID", "role": "Role", "expiration": "Expires", "cluster_url": "Cluster URL", "namespace": "Namespace", "registry_url": "Registry",
	"webhook": "Webhook", "env_vars": "Environment variables", "cert_data": "Certificate", "issuer": "Issuer", "expiry": "Expires", "details": "Number", "cvv": "CVV",
	"serial_key": "Serial key", "activation_info": "Activation", "product_name": "Product", "summary": "Summary", "parties_involved": "Parties", "signed_date": "Signed",
	"phone": "Phone", "email": "Email", "address": "Address", "emergency": "Emergency contact", "prescriptions": "Prescriptions", "allergies": "Allergies", "tags": "Tags",
}

func FieldLabel(typ, key string) string {
	if typ == "banking" && key == "type" || typ == "token" && key == "type" {
		return "Kind"
	}
	if typ == "govid" && key == "type" {
		return "Document"
	}
	if l, ok := fieldLabels[key]; ok {
		return l
	}
	l := strings.ReplaceAll(key, "_", " ")
	if l == "" {
		return key
	}
	return strings.ToUpper(l[:1]) + l[1:]
}

func isSecretField(typ, key string) bool {
	switch key {
	case "password", "secret", "key", "token", "private_key", "secret_key", "access_key", "cvv", "details", "serial_key", "webhook", "id_number", "codes", "booking_code", "insurance_id", "env_vars":
		return true
	}
	if spec, ok := ItemTypeByID(typ); ok && spec.Secret == key && key != "content" && key != "summary" {
		return true
	}
	return false
}

func fieldText(x any) string {
	switch t := x.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case []string:
		return strings.Join(t, ", ")
	case []any:
		return strings.Join(toStringList(t), ", ")
	case bool:
		if t {
			return "Yes"
		}
		return ""
	case map[string]any:
		return strings.TrimSpace(toStringValue(t["name"]))
	}
	return strings.TrimSpace(toStringValue(x))
}

func transferSubtitle(it *TransferItem, set *TransferSet) string {
	switch it.Type {
	case "password":
		parts := []string{}
		if u := it.Get("username"); u != "" {
			parts = append(parts, u)
		}
		if h := normalizeDomain(it.Get("website")); h != "" {
			parts = append(parts, h)
		} else if len(it.Passkeys) > 0 {
			parts = append(parts, it.Passkeys[0].RPID)
		}
		return strings.Join(parts, " · ")
	case "totp":
		if it.Link >= 0 && it.Link < len(set.Items) {
			return "From login " + quoteTitle(set.Items[it.Link].Title, "")
		}
		return it.Get("domain")
	case "note":
		if it.Link >= 0 && it.Link < len(set.Items) {
			return "Notes from " + quoteTitle(set.Items[it.Link].Title, "")
		}
		line := strings.SplitN(it.Get("content"), "\n", 2)[0]
		if len([]rune(line)) > 60 {
			line = string([]rune(line)[:60]) + "…"
		}
		return line
	case "banking":
		d := strings.ReplaceAll(it.Get("details"), " ", "")
		if len(d) > 4 {
			return strings.TrimSpace(it.Get("type") + " ···· " + d[len(d)-4:])
		}
		return it.Get("type")
	}
	for _, k := range []string{"service", "username", "host", "type", "email", "security_type", "issuer", "region"} {
		if v := it.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// CompareTransfer plans the file against the vault and also lists what the
// vault holds that the file does not.
func CompareTransfer(v *Vault, set *TransferSet, opt PlanOptions) (*TransferPlan, []VaultOnlyItem) {
	p := PlanTransfer(v, set, opt)
	matched := map[string]bool{}
	for _, r := range p.Rows {
		if r.Match != nil && r.Match.ID != "" {
			matched[r.Match.ID] = true
		}
	}
	types := map[string]bool{}
	for _, it := range set.Items {
		types[it.Type] = true
	}
	only := []VaultOnlyItem{}
	for _, ref := range v.ItemRefs() {
		if matched[ref.ID] {
			continue
		}
		f := v.ItemRecordFields(ref)
		ti := TransferItem{Type: ref.Spec.ID, Title: ref.Title, Fields: f, Link: -1}
		only = append(only, VaultOnlyItem{ID: ref.ID, Type: ref.Spec.ID, Title: ref.Title, Space: ref.Space, Subtitle: transferSubtitle(&ti, set)})
	}
	return p, only
}

// Apply

type TransferResult struct {
	Added         int      `json:"added"`
	Merged        int      `json:"merged"`
	Replaced      int      `json:"replaced"`
	Skipped       int      `json:"skipped"`
	Failed        int      `json:"failed"`
	PasskeysAdded int      `json:"passkeysAdded"`
	SpacesCreated []string `json:"spacesCreated"`
	Errors        []string `json:"errors"`
	IDs           []string `json:"ids"`
	Renamed       []string `json:"renamed"`
}

func (r TransferResult) Changed() int { return r.Added + r.Merged + r.Replaced }

func (v *Vault) hasSpace(space string) bool {
	if space == "" {
		return true
	}
	for _, s := range v.Spaces {
		if strings.EqualFold(s, space) {
			return true
		}
	}
	return false
}

// EnsureSpace returns the existing spelling of a space, creating it if needed.
func (v *Vault) EnsureSpace(space string) (string, bool) {
	space = normalizeSpaceName(space)
	if space == "" {
		return "", false
	}
	for _, s := range v.Spaces {
		if strings.EqualFold(s, space) {
			return s, false
		}
	}
	if len(v.Spaces) == 0 {
		v.Spaces = []string{"default"}
	}
	v.Spaces = append(v.Spaces, space)
	if v.Desktop == nil {
		v.Desktop = &DesktopState{}
	}
	if v.Desktop.SpaceCreated == nil {
		v.Desktop.SpaceCreated = map[string]time.Time{}
	}
	v.Desktop.SpaceCreated[space] = time.Now()
	return space, true
}

// ApplyTransfer re-plans against the current vault and applies one action per
// row. Rows without a decision take the planner's default.
func ApplyTransfer(v *Vault, set *TransferSet, opt PlanOptions, decisions map[int]string) (TransferResult, *TransferPlan) {
	plan := PlanTransfer(v, set, opt)
	res := TransferResult{SpacesCreated: []string{}, Errors: []string{}, IDs: []string{}, Renamed: []string{}}
	created := map[int]string{}
	for _, row := range plan.Rows {
		it := &set.Items[row.Index]
		action := row.Default
		if d, ok := decisions[row.Index]; ok {
			action = strings.ToLower(strings.TrimSpace(d))
		}
		if row.Status == RowInvalid || action == ActionSkip || action == "" {
			res.Skipped++
			continue
		}
		if action != ActionAdd && !containsString(row.Actions, action) {
			res.Skipped++
			continue
		}
		space, made := v.EnsureSpace(row.Space)
		if made {
			res.SpacesCreated = append(res.SpacesCreated, space)
		}
		target := ""
		if row.Match != nil && action != ActionAdd {
			if row.Match.Row >= 0 {
				target = created[row.Match.Row]
			} else {
				target = row.Match.ID
			}
		}
		var id string
		var err error
		var keys int
		switch {
		case (action == ActionMerge || action == ActionReplace) && target != "":
			id, keys, err = v.mergeTransferItem(target, it, action == ActionReplace)
			if err == nil {
				if action == ActionMerge {
					res.Merged++
				} else {
					res.Replaced++
				}
			}
		default:
			var renamed string
			id, renamed, keys, err = v.addTransferItem(space, it)
			if err == nil {
				res.Added++
				if renamed != "" {
					res.Renamed = append(res.Renamed, renamed)
				}
			}
		}
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, it.Title+": "+err.Error())
			continue
		}
		res.PasskeysAdded += keys
		created[row.Index] = id
		res.IDs = append(res.IDs, id)
	}
	// Codes that arrived next to their login move inside it, as on unlock.
	v.MergeLinkedTOTP()
	return res, plan
}

func (v *Vault) vaultCredentials() map[string]bool {
	out := map[string]bool{}
	for i := range v.Entries {
		for _, pk := range v.Entries[i].Passkeys {
			out[NormalizePasskeyCredentialID(pk.CredentialID)] = true
		}
	}
	return out
}

func (v *Vault) attachPasskeys(entry int, list []Passkey) int {
	have := v.vaultCredentials()
	n := 0
	for _, pk := range list {
		c := NormalizePasskeyCredentialID(pk.CredentialID)
		if c == "" || have[c] {
			continue
		}
		have[c] = true
		pk.CredentialID = c
		if pk.ID == "" {
			pk.ID = newUUID()
		}
		v.Entries[entry].Passkeys = append(v.Entries[entry].Passkeys, pk)
		n++
	}
	return n
}

func transferFields(it *TransferItem) map[string]any {
	f := map[string]any{}
	for k, val := range it.Fields {
		f[k] = val
	}
	if it.File != nil {
		f["file"] = map[string]any{"name": it.File.Name, "data": base64.StdEncoding.EncodeToString(it.File.Data)}
	}
	return f
}

func (v *Vault) addTransferItem(space string, it *TransferItem) (string, string, int, error) {
	spec, ok := ItemTypeByID(it.Type)
	if !ok {
		return "", "", 0, fmt.Errorf("unknown type %q", it.Type)
	}
	f := transferFields(it)
	title := it.Title
	renamed := ""
	for n := 2; v.titleTaken(spec, space, title, -1); n++ {
		title = fmt.Sprintf("%s (%d)", it.Title, n)
		renamed = it.Title + " → " + title
	}
	f[spec.TitleKey] = title
	ref, err := v.AddItem(it.Type, space, f)
	if err != nil {
		return "", "", 0, err
	}
	keys := 0
	if it.Type == "password" && len(it.Passkeys) > 0 {
		keys = v.attachPasskeys(ref.Index, it.Passkeys)
	}
	v.markImported(ref)
	if it.Favorite {
		v.addFavorite(ref.ID)
	}
	if len(it.History) > 0 {
		cur := v.ItemRecordFields(ref)
		hist := append([]TransferVersion(nil), it.History...)
		sort.SliceStable(hist, func(i, j int) bool { return hist[i].At.After(hist[j].At) })
		for i := len(hist) - 1; i >= 0; i-- {
			f := map[string]any{}
			for k, val := range cur {
				f[k] = val
			}
			for k, val := range hist[i].Fields {
				f[k] = val
			}
			v.pushItemVersion(ref.ID, f, hist[i].At)
		}
	}
	return ref.ID, renamed, keys, nil
}

func (v *Vault) mergeTransferItem(id string, it *TransferItem, replace bool) (string, int, error) {
	ref, ok := v.FindItem(id)
	if !ok {
		return "", 0, ErrItemNotFound
	}
	if ref.Spec.ID != it.Type {
		return "", 0, fmt.Errorf("it matches a %s, not a %s", strings.ToLower(TypeLabel(ref.Spec.ID)), strings.ToLower(TypeLabel(it.Type)))
	}
	cur := v.ItemRecordFields(ref)
	patch := map[string]any{}
	urls := toStringList(cur["urls"])
	addURL := func(u string) {
		h := normalizeDomain(u)
		if h == "" || containsString(loginHosts(map[string]any{"website": cur["website"], "urls": urls}), h) {
			return
		}
		urls = append(urls, u)
		patch["urls"] = urls
	}
	for k, val := range it.Fields {
		if k == ref.Spec.TitleKey {
			continue
		}
		inc := fieldText(val)
		if inc == "" {
			continue
		}
		have := fieldText(cur[k])
		switch k {
		case "urls":
			for _, u := range toStringList(val) {
				addURL(u)
			}
		case "website":
			switch {
			case have == "":
				patch[k] = val
			case normalizeDomain(have) == normalizeDomain(inc):
			case replace:
				patch[k] = val
				addURL(have)
			default:
				addURL(inc)
			}
		case "notes":
			if replace {
				patch[k] = val
			} else if j := joinNotes(have, inc); j != have {
				patch[k] = j
			}
		default:
			if have == "" || (replace && have != inc) {
				patch[k] = val
			}
		}
	}
	if replace && it.File != nil && len(it.File.Data) > 0 {
		patch["file"] = map[string]any{"name": it.File.Name, "data": base64.StdEncoding.EncodeToString(it.File.Data)}
	}
	if len(patch) > 0 {
		var err error
		v.pushItemVersion(id, cur, time.Now())
		ref, _, err = v.UpdateItem(id, patch, nil)
		if err != nil {
			return "", 0, err
		}
	}
	keys := 0
	if it.Type == "password" && len(it.Passkeys) > 0 {
		keys = v.attachPasskeys(ref.Index, it.Passkeys)
	}
	if it.Favorite {
		v.addFavorite(ref.ID)
	}
	return ref.ID, keys, nil
}

func (v *Vault) addFavorite(id string) {
	if v.isFavoriteID(id) {
		return
	}
	if v.Desktop == nil {
		v.Desktop = &DesktopState{}
	}
	v.Desktop.Favorites = append(v.Desktop.Favorites, id)
}

func (v *Vault) markImported(ref VaultItemRef) {
	v.ensureSecretTelemetry()
	key := secretTelemetryKey(ref.Spec.Category, v.telemetryIdentifier(ref.Spec, v.ItemElem(ref)), ref.Space)
	now := time.Now()
	t := v.SecretTelemetry[key]
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.CreatedBy = resolveTelemetryActor()
	t.UpdatedAt = now
	t.Source = "import"
	v.SecretTelemetry[key] = t
}

// pushItemVersion records an earlier state the way the app's item history
// does: newest first, at most 20 per item.
func (v *Vault) pushItemVersion(id string, f map[string]any, at time.Time) {
	if v.Desktop == nil {
		v.Desktop = &DesktopState{}
	}
	if v.Desktop.Versions == nil {
		v.Desktop.Versions = map[string][]ItemVersion{}
	}
	if at.IsZero() {
		at = time.Now()
	}
	list := append([]ItemVersion{{F: f, TS: at}}, v.Desktop.Versions[id]...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].TS.After(list[j].TS) })
	if len(list) > 20 {
		list = list[:20]
	}
	v.Desktop.Versions[id] = list
}

func differentAccounts(a, b map[string]any) bool {
	ua, ub := strings.ToLower(fieldText(a["username"])), strings.ToLower(fieldText(b["username"]))
	return ua != "" && ub != "" && ua != ub
}

// renamedCopy finds "Title (2)" and later copies that an earlier import made
// when it kept two accounts with the same name.
func (ix *planIndex) renamedCopy(it *TransferItem, space string) (planEntry, bool) {
	for n := 2; n <= 50; n++ {
		e, ok := ix.byKey[itemKey(it.Type, space, fmt.Sprintf("%s (%d)", it.Title, n))]
		if !ok {
			return planEntry{}, false
		}
		if !differentAccounts(it.Fields, e.fields) {
			return e, true
		}
	}
	return planEntry{}, false
}
