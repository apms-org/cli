package apm

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrItemExists = errors.New("an item with that name already exists in this space")
var ErrItemNotFound = errors.New("item not found")
var ErrItemInvalid = errors.New("invalid item")

type Passkey struct {
	ID              string          `json:"id"`
	RPID            string          `json:"rpId"`
	UserName        string          `json:"userName"`
	UserDisplayName string          `json:"userDisplayName"`
	UserHandle      string          `json:"userHandle"`
	CredentialID    string          `json:"credentialId"`
	PrivateKey      json.RawMessage `json:"privateKey,omitempty"`
	SignCount       int64           `json:"signCount"`
	CreatedAt       string          `json:"createdAt"`
	LastUsedAt      *string         `json:"lastUsedAt"`
	Label           string          `json:"label,omitempty"`
}

type TrashedItem struct {
	ID        string           `json:"id"`
	Type      string           `json:"type"`
	Space     string           `json:"space,omitempty"`
	Title     string           `json:"title"`
	Data      json.RawMessage  `json:"data"`
	Domain    string           `json:"domain,omitempty"`
	Telemetry *SecretTelemetry `json:"telemetry,omitempty"`
	Favorite  bool             `json:"favorite,omitempty"`
	DeletedAt time.Time        `json:"deleted_at"`
}

type ItemVersion struct {
	F  map[string]any `json:"f"`
	TS time.Time      `json:"ts"`
}

type DesktopState struct {
	Name         string                   `json:"name,omitempty"`
	Created      time.Time                `json:"created,omitempty"`
	Favorites    []string                 `json:"favorites,omitempty"`
	SpaceColors  map[string]int           `json:"space_colors,omitempty"`
	SpaceCreated map[string]time.Time     `json:"space_created,omitempty"`
	Trash        []TrashedItem            `json:"trash,omitempty"`
	Versions     map[string][]ItemVersion `json:"versions,omitempty"`
	Settings     map[string]any           `json:"settings,omitempty"`
	MCPEnabled   bool                     `json:"mcp_enabled,omitempty"`
	MCPClients   map[string]bool          `json:"mcp_clients,omitempty"`
	SyncAuto     bool                     `json:"sync_auto,omitempty"`
	SyncLast     map[string]time.Time     `json:"sync_last,omitempty"`
	SyncError    map[string]string        `json:"sync_error,omitempty"`
	Policy       string                   `json:"policy,omitempty"`

	RecoveryKeyCreated   time.Time `json:"recovery_key_created,omitempty"`
	RecoveryCodesCreated time.Time `json:"recovery_codes_created,omitempty"`
	QuorumCreated        time.Time `json:"quorum_created,omitempty"`
}

type ItemTypeSpec struct {
	ID             string
	VaultField     string
	JSONKey        string
	TitleField     string
	TitleKey       string
	Category       string
	Secret         string
	TelemetryField string
	Media          bool
}

var ItemTypes = []ItemTypeSpec{
	{ID: "password", VaultField: "Entries", JSONKey: "entries", TitleField: "Account", TitleKey: "account", Category: "PASSWORD", Secret: "password"},
	{ID: "totp", VaultField: "TOTPEntries", JSONKey: "totp_entries", TitleField: "Account", TitleKey: "account", Category: "TOTP", Secret: "secret"},
	{ID: "note", VaultField: "SecureNotes", JSONKey: "secure_notes", TitleField: "Name", TitleKey: "name", Category: "NOTE", Secret: "content"},
	{ID: "wifi", VaultField: "WiFiCredentials", JSONKey: "wifi_credentials", TitleField: "SSID", TitleKey: "ssid", Category: "WIFI", Secret: "password"},
	{ID: "govid", VaultField: "GovIDs", JSONKey: "gov_ids", TitleField: "Name", TitleKey: "name", Category: "GOVID", Secret: "id_number", TelemetryField: "IDNumber"},
	{ID: "medical", VaultField: "MedicalRecords", JSONKey: "medical_records", TitleField: "Label", TitleKey: "label", Category: "MEDICAL", Secret: "insurance_id"},
	{ID: "travel", VaultField: "TravelDocs", JSONKey: "travel_docs", TitleField: "Label", TitleKey: "label", Category: "TRAVEL", Secret: "booking_code"},
	{ID: "contact", VaultField: "Contacts", JSONKey: "contacts", TitleField: "Name", TitleKey: "name", Category: "CONTACT"},
	{ID: "recovery", VaultField: "RecoveryCodeItems", JSONKey: "recovery_codes", TitleField: "Service", TitleKey: "service", Category: "RECOVERY", Secret: "codes"},
	{ID: "apikey", VaultField: "APIKeys", JSONKey: "api_keys", TitleField: "Name", TitleKey: "name", Category: "APIKEY", Secret: "key"},
	{ID: "token", VaultField: "Tokens", JSONKey: "tokens", TitleField: "Name", TitleKey: "name", Category: "TOKEN", Secret: "token"},
	{ID: "ssh_key", VaultField: "SSHKeys", JSONKey: "ssh_keys", TitleField: "Name", TitleKey: "name", Category: "SSHKEY", Secret: "private_key"},
	{ID: "ssh_config", VaultField: "SSHConfigs", JSONKey: "ssh_configs", TitleField: "Alias", TitleKey: "alias", Category: "SSHCONFIG", Secret: "private_key"},
	{ID: "cloud", VaultField: "CloudCredentialsItems", JSONKey: "cloud_credentials_items", TitleField: "Label", TitleKey: "label", Category: "CLOUDCRED", Secret: "secret_key"},
	{ID: "k8s", VaultField: "K8sSecrets", JSONKey: "k8s_secrets", TitleField: "Name", TitleKey: "name", Category: "K8S"},
	{ID: "docker", VaultField: "DockerRegistries", JSONKey: "docker_registries", TitleField: "Name", TitleKey: "name", Category: "DOCKER", Secret: "token"},
	{ID: "cicd", VaultField: "CICDSecrets", JSONKey: "cicd_secrets", TitleField: "Name", TitleKey: "name", Category: "CICD", Secret: "webhook"},
	{ID: "certificate", VaultField: "Certificates", JSONKey: "certificates", TitleField: "Label", TitleKey: "label", Category: "CERTIFICATE", Secret: "private_key"},
	{ID: "banking", VaultField: "BankingItems", JSONKey: "banking_items", TitleField: "Label", TitleKey: "label", Category: "BANKING", Secret: "details"},
	{ID: "license", VaultField: "SoftwareLicenses", JSONKey: "software_licenses", TitleField: "ProductName", TitleKey: "product_name", Category: "LICENSE", Secret: "serial_key"},
	{ID: "legal", VaultField: "LegalContracts", JSONKey: "legal_contracts", TitleField: "Name", TitleKey: "name", Category: "CONTRACT"},
	{ID: "document", VaultField: "Documents", JSONKey: "documents", TitleField: "Name", TitleKey: "name", Category: "DOCUMENT", Secret: "password", Media: true},
	{ID: "photo", VaultField: "PhotoFiles", JSONKey: "photo_files", TitleField: "Name", TitleKey: "name", Category: "PHOTO", Media: true},
	{ID: "audio", VaultField: "AudioFiles", JSONKey: "audio_files", TitleField: "Name", TitleKey: "name", Category: "AUDIO", Media: true},
	{ID: "video", VaultField: "VideoFiles", JSONKey: "video_files", TitleField: "Name", TitleKey: "name", Category: "VIDEO", Media: true},
}

func ItemTypeByID(id string) (ItemTypeSpec, bool) {
	for _, s := range ItemTypes {
		if s.ID == id {
			return s, true
		}
	}
	return ItemTypeSpec{}, false
}

func ItemTypeByJSONKey(key string) (ItemTypeSpec, bool) {
	for _, s := range ItemTypes {
		if s.JSONKey == key {
			return s, true
		}
	}
	return ItemTypeSpec{}, false
}

func ItemTypeByCategory(category string) (ItemTypeSpec, bool) {
	c := strings.ToUpper(strings.TrimSpace(category))
	switch c {
	case "LEGAL":
		c = "CONTRACT"
	case "API_KEY":
		c = "APIKEY"
	case "SSH_KEY":
		c = "SSHKEY"
	case "SSH_CONFIG":
		c = "SSHCONFIG"
	case "CLOUD", "CLOUD_CREDENTIALS":
		c = "CLOUDCRED"
	case "GOV_ID":
		c = "GOVID"
	}
	for _, s := range ItemTypes {
		if s.Category == c {
			return s, true
		}
	}
	return ItemTypeSpec{}, false
}

type VaultItemRef struct {
	Spec  ItemTypeSpec
	Index int
	ID    string
	Title string
	Space string
}

func ItemID(typ, space, title string) string {
	sum := sha256.Sum256([]byte(typ + "\x00" + space + "\x00" + title))
	return hex.EncodeToString(sum[:])[:16]
}

type fieldInfo struct {
	Index int
	Name  string
	JSON  string
	Type  reflect.Type
}

var fieldCache sync.Map

func structFields(t reflect.Type) []fieldInfo {
	if v, ok := fieldCache.Load(t); ok {
		return v.([]fieldInfo)
	}
	var out []fieldInfo
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, fieldInfo{Index: i, Name: f.Name, JSON: name, Type: f.Type})
	}
	fieldCache.Store(t, out)
	return out
}

func (v *Vault) itemSlice(spec ItemTypeSpec) reflect.Value {
	return reflect.ValueOf(v).Elem().FieldByName(spec.VaultField)
}

func (v *Vault) ItemElem(ref VaultItemRef) reflect.Value {
	return v.itemSlice(ref.Spec).Index(ref.Index)
}

func elemString(elem reflect.Value, field string) string {
	f := elem.FieldByName(field)
	if !f.IsValid() || f.Kind() != reflect.String {
		return ""
	}
	return f.String()
}

func (v *Vault) ItemRefs() []VaultItemRef {
	var out []VaultItemRef
	seen := map[string]int{}
	for _, spec := range ItemTypes {
		s := v.itemSlice(spec)
		for i := 0; i < s.Len(); i++ {
			elem := s.Index(i)
			title := elemString(elem, spec.TitleField)
			space := elemString(elem, "Space")
			base := ItemID(spec.ID, space, title)
			seen[base]++
			id := base
			if n := seen[base]; n > 1 {
				id = base + "-" + strconv.Itoa(n)
			}
			out = append(out, VaultItemRef{Spec: spec, Index: i, ID: id, Title: title, Space: space})
		}
	}
	return out
}

func (v *Vault) FindItem(id string) (VaultItemRef, bool) {
	for _, r := range v.ItemRefs() {
		if r.ID == id {
			return r, true
		}
	}
	return VaultItemRef{}, false
}

func (v *Vault) findRefAt(spec ItemTypeSpec, index int) (VaultItemRef, bool) {
	for _, r := range v.ItemRefs() {
		if r.Spec.ID == spec.ID && r.Index == index {
			return r, true
		}
	}
	return VaultItemRef{}, false
}

func (v *Vault) telemetryIdentifier(spec ItemTypeSpec, elem reflect.Value) string {
	if spec.TelemetryField != "" {
		if s := elemString(elem, spec.TelemetryField); s != "" {
			return s
		}
	}
	return elemString(elem, spec.TitleField)
}

func (v *Vault) LogItemEvent(action string, spec ItemTypeSpec, identifier, space string) {
	prev := v.CurrentSpace
	v.CurrentSpace = space
	v.logHistory(action, spec.Category, identifier)
	v.CurrentSpace = prev
}

func (v *Vault) ItemTelemetry(ref VaultItemRef) SecretTelemetry {
	elem := v.ItemElem(ref)
	t, _ := v.GetSecretTelemetry(ref.Spec.Category, v.telemetryIdentifier(ref.Spec, elem), ref.Space)
	return t
}

func (v *Vault) SetItemTelemetryFlags(ref VaultItemRef, privilege *string, exposed *bool) {
	v.ensureSecretTelemetry()
	elem := v.ItemElem(ref)
	key := secretTelemetryKey(ref.Spec.Category, v.telemetryIdentifier(ref.Spec, elem), ref.Space)
	t, ok := v.SecretTelemetry[key]
	if !ok {
		if found, fok := v.GetSecretTelemetry(ref.Spec.Category, v.telemetryIdentifier(ref.Spec, elem), ref.Space); fok {
			t = found
		}
	}
	if privilege != nil {
		t.Privilege = strings.TrimSpace(*privilege)
	}
	if exposed != nil {
		t.Exposed = *exposed
	}
	v.SecretTelemetry[key] = t
}

func (v *Vault) moveTelemetry(category, oldID, oldSpace, newID, newSpace string) {
	if v.SecretTelemetry == nil {
		return
	}
	oldKey := secretTelemetryKey(category, oldID, oldSpace)
	newKey := secretTelemetryKey(category, newID, newSpace)
	if oldKey == newKey {
		return
	}
	if t, ok := v.SecretTelemetry[oldKey]; ok {
		delete(v.SecretTelemetry, oldKey)
		v.SecretTelemetry[newKey] = t
	}
}

func MimeForFileName(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".svg":
		return "image/svg+xml"
	case ".heic":
		return "image/heic"
	case ".mov":
		return "video/quicktime"
	case ".m4a":
		return "audio/mp4"
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	case ".pdf":
		return "application/pdf"
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return strings.Split(t, ";")[0]
	}
	return "application/octet-stream"
}

func ItemFields(spec ItemTypeSpec, elem reflect.Value) map[string]any {
	out := map[string]any{}
	for _, fi := range structFields(elem.Type()) {
		key := fi.JSON
		if strings.EqualFold(key, "space") || key == "passkeys" {
			continue
		}
		fv := elem.Field(fi.Index)
		switch {
		case fi.Type == reflect.TypeOf([]byte(nil)):
			continue
		case fi.Type == reflect.TypeOf([]CustomField(nil)):
			list := []map[string]any{}
			for _, cf := range fv.Interface().([]CustomField) {
				list = append(list, map[string]any{"label": cf.Label, "value": cf.Value, "hidden": cf.Hidden})
			}
			out[key] = list
		case fi.Type == reflect.TypeOf(time.Time{}):
			t := fv.Interface().(time.Time)
			if t.IsZero() {
				out[key] = ""
			} else {
				out[key] = t.Format("2006-01-02")
			}
		case fi.Type.Kind() == reflect.Slice && fi.Type.Elem().Kind() == reflect.String:
			list := make([]string, fv.Len())
			for i := 0; i < fv.Len(); i++ {
				list[i] = fv.Index(i).String()
			}
			out[key] = list
		case fi.Type.Kind() == reflect.String:
			out[key] = fv.String()
		case fi.Type.Kind() == reflect.Bool:
			out[key] = fv.Bool()
		case fi.Type.Kind() >= reflect.Int && fi.Type.Kind() <= reflect.Int64:
			out[key] = fv.Int()
		}
	}
	if spec.Media {
		name := elemString(elem, "FileName")
		content := elem.FieldByName("Content")
		size := 0
		if content.IsValid() {
			size = content.Len()
		}
		delete(out, "file_name")
		out["file"] = map[string]any{"name": name, "size": size, "mime": MimeForFileName(name)}
	}
	return out
}

func toStringValue(x any) string {
	switch t := x.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func toStringList(x any) []string {
	switch t := x.(type) {
	case nil:
		return nil
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s := strings.TrimSpace(toStringValue(e))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		var out []string
		for _, part := range strings.FieldsFunc(t, func(r rune) bool { return r == '\n' || r == ',' }) {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toCustomFields(x any) []CustomField {
	var out []CustomField
	add := func(label, value string, hidden bool) {
		label, value = strings.TrimSpace(label), strings.TrimSpace(value)
		if label == "" && value == "" {
			return
		}
		out = append(out, CustomField{Label: label, Value: value, Hidden: hidden})
	}
	switch t := x.(type) {
	case []CustomField:
		for _, cf := range t {
			add(cf.Label, cf.Value, cf.Hidden)
		}
	case []any:
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				add(toStringValue(m["label"]), toStringValue(m["value"]), toBool(m["hidden"]))
			}
		}
	case []map[string]any:
		for _, m := range t {
			add(toStringValue(m["label"]), toStringValue(m["value"]), toBool(m["hidden"]))
		}
	}
	return out
}

func toBool(x any) bool {
	switch t := x.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "true" || s == "yes" || s == "1" || s == "on"
	case float64:
		return t != 0
	}
	return false
}

func decodeFileData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "data:") {
		if i := strings.Index(s, ","); i >= 0 {
			s = s[i+1:]
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

func SetItemFields(spec ItemTypeSpec, elem reflect.Value, f map[string]any) error {
	for _, fi := range structFields(elem.Type()) {
		key := fi.JSON
		if strings.EqualFold(key, "space") || key == "passkeys" {
			continue
		}
		if spec.Media && (key == "content" || key == "file_name") {
			continue
		}
		raw, ok := f[key]
		if !ok {
			continue
		}
		fv := elem.Field(fi.Index)
		switch {
		case fi.Type == reflect.TypeOf([]byte(nil)):
			continue
		case fi.Type == reflect.TypeOf([]CustomField(nil)):
			list := toCustomFields(raw)
			if list == nil {
				fv.Set(reflect.Zero(fi.Type))
			} else {
				fv.Set(reflect.ValueOf(list))
			}
		case spec.ID == "password" && key == "totp":
			secret, err := NormalizeLoginTOTP(toStringValue(raw))
			if err != nil {
				return err
			}
			fv.SetString(secret)
		case fi.Type == reflect.TypeOf(time.Time{}):
			s := strings.TrimSpace(toStringValue(raw))
			if s == "" {
				fv.Set(reflect.ValueOf(time.Time{}))
				continue
			}
			var t time.Time
			var err error
			for _, layout := range []string{"2006-01-02", time.RFC3339, time.RFC3339Nano, "2006-01"} {
				t, err = time.Parse(layout, s)
				if err == nil {
					break
				}
			}
			if err != nil {
				return fmt.Errorf("%w: %s is not a date (use YYYY-MM-DD)", ErrItemInvalid, key)
			}
			fv.Set(reflect.ValueOf(t))
		case fi.Type.Kind() == reflect.Slice && fi.Type.Elem().Kind() == reflect.String:
			list := toStringList(raw)
			if list == nil {
				fv.Set(reflect.Zero(fi.Type))
			} else {
				fv.Set(reflect.ValueOf(list))
			}
		case fi.Type.Kind() == reflect.String:
			fv.SetString(toStringValue(raw))
		case fi.Type.Kind() == reflect.Bool:
			fv.SetBool(toBool(raw))
		case fi.Type.Kind() >= reflect.Int && fi.Type.Kind() <= reflect.Int64:
			n, _ := strconv.ParseInt(strings.TrimSpace(toStringValue(raw)), 10, 64)
			fv.SetInt(n)
		}
	}
	if spec.Media {
		if file, ok := f["file"].(map[string]any); ok {
			if name := strings.TrimSpace(toStringValue(file["name"])); name != "" {
				elem.FieldByName("FileName").SetString(filepath.Base(name))
			}
			if data, ok := file["data"]; ok && data != nil {
				s := toStringValue(data)
				if s != "" {
					b, err := decodeFileData(s)
					if err != nil {
						return fmt.Errorf("%w: file data is not valid base64", ErrItemInvalid)
					}
					elem.FieldByName("Content").SetBytes(b)
				}
			}
		}
	}
	return nil
}

func (v *Vault) totpDomainFor(account string) string {
	var keys []string
	for d, acc := range v.TOTPDomainLinks {
		if acc == account {
			keys = append(keys, d)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func normalizeDomain(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	return strings.TrimPrefix(d, "www.")
}

func (v *Vault) setTOTPDomain(account, domain string) {
	for d, acc := range v.TOTPDomainLinks {
		if acc == account {
			delete(v.TOTPDomainLinks, d)
		}
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return
	}
	if v.TOTPDomainLinks == nil {
		v.TOTPDomainLinks = map[string]string{}
	}
	v.TOTPDomainLinks[domain] = account
}

func (v *Vault) ItemRecordFields(ref VaultItemRef) map[string]any {
	elem := v.ItemElem(ref)
	f := ItemFields(ref.Spec, elem)
	if ref.Spec.ID == "totp" {
		f["domain"] = v.totpDomainFor(ref.Title)
	}
	return f
}

func (v *Vault) ItemPasskeys(ref VaultItemRef) []Passkey {
	if ref.Spec.ID != "password" {
		return nil
	}
	return v.Entries[ref.Index].Passkeys
}

func (v *Vault) titleTaken(spec ItemTypeSpec, space, title string, skipIndex int) bool {
	s := v.itemSlice(spec)
	for i := 0; i < s.Len(); i++ {
		if i == skipIndex {
			continue
		}
		e := s.Index(i)
		if strings.EqualFold(strings.TrimSpace(elemString(e, spec.TitleField)), strings.TrimSpace(title)) && strings.EqualFold(elemString(e, "Space"), space) {
			return true
		}
	}
	return false
}

func (v *Vault) AddItem(typeID, space string, f map[string]any) (VaultItemRef, error) {
	spec, ok := ItemTypeByID(typeID)
	if !ok {
		return VaultItemRef{}, fmt.Errorf("%w: unknown type %q", ErrItemInvalid, typeID)
	}
	s := v.itemSlice(spec)
	elem := reflect.New(s.Type().Elem()).Elem()
	if err := SetItemFields(spec, elem, f); err != nil {
		return VaultItemRef{}, err
	}
	title := strings.TrimSpace(elemString(elem, spec.TitleField))
	if title == "" {
		return VaultItemRef{}, fmt.Errorf("%w: a name is required", ErrItemInvalid)
	}
	elem.FieldByName(spec.TitleField).SetString(title)
	elem.FieldByName("Space").SetString(space)
	if v.titleTaken(spec, space, title, -1) {
		return VaultItemRef{}, ErrItemExists
	}
	s.Set(reflect.Append(s, elem))
	index := s.Len() - 1
	if spec.ID == "totp" {
		if d, ok := f["domain"]; ok {
			v.setTOTPDomain(title, toStringValue(d))
		}
	}
	v.LogItemEvent("ADD", spec, v.telemetryIdentifier(spec, v.itemSlice(spec).Index(index)), space)
	ref, _ := v.findRefAt(spec, index)
	return ref, nil
}

func secretValue(f map[string]any, key string) string {
	if key == "" {
		return ""
	}
	switch t := f[key].(type) {
	case []string:
		return strings.Join(t, "\n")
	default:
		return toStringValue(t)
	}
}

func (v *Vault) UpdateItem(id string, f map[string]any, space *string) (VaultItemRef, map[string]any, error) {
	ref, ok := v.FindItem(id)
	if !ok {
		return VaultItemRef{}, nil, ErrItemNotFound
	}
	spec := ref.Spec
	s := v.itemSlice(spec)
	current := s.Index(ref.Index)
	before := v.ItemRecordFields(ref)
	oldTelemetryID := v.telemetryIdentifier(spec, current)
	oldSpace := ref.Space
	oldTitle := ref.Title

	next := reflect.New(current.Type()).Elem()
	next.Set(current)
	if err := SetItemFields(spec, next, f); err != nil {
		return VaultItemRef{}, nil, err
	}
	title := strings.TrimSpace(elemString(next, spec.TitleField))
	if title == "" {
		return VaultItemRef{}, nil, fmt.Errorf("%w: a name is required", ErrItemInvalid)
	}
	next.FieldByName(spec.TitleField).SetString(title)
	newSpace := oldSpace
	if space != nil {
		newSpace = *space
	}
	next.FieldByName("Space").SetString(newSpace)
	if (!strings.EqualFold(title, oldTitle) || !strings.EqualFold(newSpace, oldSpace)) && v.titleTaken(spec, newSpace, title, ref.Index) {
		return VaultItemRef{}, nil, ErrItemExists
	}
	current.Set(next)

	if spec.ID == "totp" {
		domain := toStringValue(before["domain"])
		if d, ok := f["domain"]; ok {
			domain = toStringValue(d)
		}
		if title != oldTitle {
			v.setTOTPDomain(oldTitle, "")
		}
		v.setTOTPDomain(title, domain)
	}

	newTelemetryID := v.telemetryIdentifier(spec, current)
	v.moveTelemetry(spec.Category, oldTelemetryID, oldSpace, newTelemetryID, newSpace)
	v.LogItemEvent("EDIT", spec, newTelemetryID, newSpace)
	after := ItemFields(spec, current)
	if spec.Secret != "" && secretValue(before, spec.Secret) != secretValue(after, spec.Secret) {
		v.ensureSecretTelemetry()
		key := secretTelemetryKey(spec.Category, newTelemetryID, newSpace)
		t := v.SecretTelemetry[key]
		t.LastRotation = time.Now()
		v.SecretTelemetry[key] = t
	}
	newRef, _ := v.findRefAt(spec, ref.Index)
	return newRef, before, nil
}

func (v *Vault) RemoveItem(id string) (TrashedItem, error) {
	ref, ok := v.FindItem(id)
	if !ok {
		return TrashedItem{}, ErrItemNotFound
	}
	spec := ref.Spec
	s := v.itemSlice(spec)
	elem := s.Index(ref.Index)
	data, err := json.Marshal(elem.Interface())
	if err != nil {
		return TrashedItem{}, err
	}
	tel, hasTel := v.GetSecretTelemetry(spec.Category, v.telemetryIdentifier(spec, elem), ref.Space)
	now := time.Now()
	t := TrashedItem{
		Type:      spec.ID,
		Space:     ref.Space,
		Title:     ref.Title,
		Data:      data,
		DeletedAt: now,
	}
	if hasTel {
		tc := tel
		t.Telemetry = &tc
	}
	if spec.ID == "totp" {
		t.Domain = v.totpDomainFor(ref.Title)
		v.setTOTPDomain(ref.Title, "")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", spec.ID, ref.Space, ref.Title, now.UnixNano())))
	t.ID = "t" + hex.EncodeToString(sum[:])[:15]
	identifier := v.telemetryIdentifier(spec, elem)
	s.Set(reflect.AppendSlice(s.Slice(0, ref.Index), s.Slice(ref.Index+1, s.Len())))
	v.LogItemEvent("DEL", spec, identifier, ref.Space)
	return t, nil
}

func (v *Vault) RestoreTrashedItem(t TrashedItem) (VaultItemRef, error) {
	spec, ok := ItemTypeByID(t.Type)
	if !ok {
		return VaultItemRef{}, fmt.Errorf("%w: unknown type %q", ErrItemInvalid, t.Type)
	}
	s := v.itemSlice(spec)
	elem := reflect.New(s.Type().Elem())
	if err := json.Unmarshal(t.Data, elem.Interface()); err != nil {
		return VaultItemRef{}, err
	}
	e := elem.Elem()
	e.FieldByName("Space").SetString(t.Space)
	title := elemString(e, spec.TitleField)
	if v.titleTaken(spec, t.Space, title, -1) {
		return VaultItemRef{}, ErrItemExists
	}
	s.Set(reflect.Append(s, e))
	index := s.Len() - 1
	identifier := v.telemetryIdentifier(spec, e)
	v.LogItemEvent("ADD", spec, identifier, t.Space)
	if t.Telemetry != nil {
		v.ensureSecretTelemetry()
		v.SecretTelemetry[secretTelemetryKey(spec.Category, identifier, t.Space)] = *t.Telemetry
	}
	if spec.ID == "totp" && t.Domain != "" {
		v.setTOTPDomain(title, t.Domain)
	}
	ref, _ := v.findRefAt(spec, index)
	return ref, nil
}

func (t TrashedItem) Fields() map[string]any {
	spec, ok := ItemTypeByID(t.Type)
	if !ok {
		return map[string]any{}
	}
	var probe Vault
	elem := reflect.New(probe.itemSlice(spec).Type().Elem())
	if err := json.Unmarshal(t.Data, elem.Interface()); err != nil {
		return map[string]any{}
	}
	f := ItemFields(spec, elem.Elem())
	if spec.ID == "totp" {
		f["domain"] = t.Domain
	}
	return f
}

func (t TrashedItem) Passkeys() []Passkey {
	if t.Type != "password" {
		return nil
	}
	var e Entry
	if err := json.Unmarshal(t.Data, &e); err != nil {
		return nil
	}
	return e.Passkeys
}

func (t TrashedItem) FileContent() (string, []byte, bool) {
	spec, ok := ItemTypeByID(t.Type)
	if !ok || !spec.Media {
		return "", nil, false
	}
	var probe Vault
	elem := reflect.New(probe.itemSlice(spec).Type().Elem())
	if err := json.Unmarshal(t.Data, elem.Interface()); err != nil {
		return "", nil, false
	}
	e := elem.Elem()
	return elemString(e, "FileName"), e.FieldByName("Content").Bytes(), true
}

func (v *Vault) ItemFileContent(ref VaultItemRef) (string, []byte, bool) {
	if !ref.Spec.Media {
		return "", nil, false
	}
	e := v.ItemElem(ref)
	return elemString(e, "FileName"), e.FieldByName("Content").Bytes(), true
}

func (v *Vault) RecordItemAccess(ref VaultItemRef) {
	v.LogItemEvent("GET", ref.Spec, v.telemetryIdentifier(ref.Spec, v.ItemElem(ref)), ref.Space)
}

func (v *Vault) TOTPOrderKey(ref VaultItemRef) string {
	space := strings.TrimSpace(ref.Space)
	if space == "" {
		space = "default"
	}
	return strings.ToLower(space + "|" + strings.TrimSpace(ref.Title))
}

func (v *Vault) RenameSpaceEverywhere(oldName, newName string) {
	for _, spec := range ItemTypes {
		s := v.itemSlice(spec)
		for i := 0; i < s.Len(); i++ {
			e := s.Index(i)
			if elemString(e, "Space") == oldName {
				e.FieldByName("Space").SetString(newName)
			}
		}
	}
	if v.SecretTelemetry != nil {
		moved := map[string]SecretTelemetry{}
		for k, t := range v.SecretTelemetry {
			cat, id, sp := parseSecretTelemetryKey(k)
			if sp == oldName && cat != "" {
				moved[secretTelemetryKey(cat, id, newName)] = t
				delete(v.SecretTelemetry, k)
			}
		}
		for k, t := range moved {
			v.SecretTelemetry[k] = t
		}
	}
	oldPrefix := strings.ToLower(spaceOrDefault(oldName) + "|")
	newPrefix := strings.ToLower(spaceOrDefault(newName) + "|")
	for i, key := range v.TOTPOrder {
		if strings.HasPrefix(strings.ToLower(key), oldPrefix) {
			v.TOTPOrder[i] = newPrefix + key[len(oldPrefix):]
		}
	}
	if v.CurrentSpace == oldName {
		v.CurrentSpace = newName
	}
}

func spaceOrDefault(s string) string {
	if strings.TrimSpace(s) == "" {
		return "default"
	}
	return s
}

func (v *Vault) PasskeyOwner(credentialID string) (int, int, bool) {
	for i := range v.Entries {
		for j := range v.Entries[i].Passkeys {
			if v.Entries[i].Passkeys[j].CredentialID == credentialID {
				return i, j, true
			}
		}
	}
	return 0, 0, false
}

func MaskEmailHint(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		if email == "" {
			return ""
		}
		return "•••"
	}
	local := []rune(email[:at])
	return string(local[0]) + "•••" + email[at:]
}

func ParseVaultHeaderRecovery(data []byte) (RecoveryData, bool) {
	if len(data) < len(VaultHeader)+1 || string(data[:len(VaultHeader)]) != VaultHeader {
		return RecoveryData{}, false
	}
	offset := len(VaultHeader)
	if data[offset] != 4 {
		return RecoveryData{}, false
	}
	offset++
	if offset+2 > len(data) {
		return RecoveryData{}, false
	}
	pLen := int(data[offset])<<8 | int(data[offset+1])
	rOffset := offset + 2 + pLen
	if rOffset+2 > len(data) {
		return RecoveryData{}, false
	}
	rLen := int(data[rOffset])<<8 | int(data[rOffset+1])
	start := rOffset + 2
	if start+rLen > len(data) {
		return RecoveryData{}, false
	}
	var rec RecoveryData
	if err := json.Unmarshal(data[start:start+rLen], &rec); err != nil {
		return RecoveryData{}, false
	}
	return rec, true
}
