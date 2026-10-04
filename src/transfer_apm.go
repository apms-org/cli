package apm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// APM's own export. Version 2 holds every item type with its space, favorite
// flag, passkeys (private keys included) and, when asked, file contents.
// Encrypted exports wrap the JSON with EncryptData: Argon2id, AES-256-GCM and
// an HMAC-SHA256 over the salt and ciphertext.

const apmExportFormat = "apm-export"

type apmExportDoc struct {
	Format    string          `json:"format"`
	Version   int             `json:"version"`
	Created   string          `json:"created,omitempty"`
	Vault     string          `json:"vault,omitempty"`
	Counts    map[string]int  `json:"counts,omitempty"`
	Items     []apmExportItem `json:"items,omitempty"`
	Encrypted bool            `json:"encrypted,omitempty"`
	Cipher    string          `json:"cipher,omitempty"`
	KDF       string          `json:"kdf,omitempty"`
	Data      string          `json:"data,omitempty"`
}

type apmExportItem struct {
	Type     string          `json:"type"`
	Title    string          `json:"title"`
	Space    string          `json:"space,omitempty"`
	Favorite bool            `json:"favorite,omitempty"`
	Fields   map[string]any  `json:"fields"`
	Passkeys []Passkey       `json:"passkeys,omitempty"`
	File     *apmExportFileT `json:"file,omitempty"`
}

type apmExportFileT struct {
	Name string `json:"name"`
	Data string `json:"data,omitempty"`
}

func init() {
	RegisterTransferFormat(TransferFormat{
		ID: "apm", Label: "APM export", Vendor: "apm", Ext: []string{".json", ".apm"},
		Help:   "Exported with pm export or from Settings > Import and export in the APM app. Encrypted exports ask for the password chosen when exporting.",
		Detect: detectAPM, Parse: parseAPM,
	})
	RegisterTransferFormat(TransferFormat{
		ID: "apm-vault", Label: "APM vault or backup", Vendor: "apm", Ext: []string{".dat"},
		Help: "A vault.dat file or a backup saved from Settings > Import and export. It opens with that vault's master password.",
		Detect: func(name string, data []byte) int {
			if bytes.HasPrefix(data, []byte(VaultHeader)) {
				return 100
			}
			return 0
		},
		Parse: parseAPMVault,
	})
	RegisterTransferExporter(TransferExporter{
		ID: "apm", Label: "APM", Vendor: "apm", Ext: "json", Passkeys: true, Encryption: true, Files: true, Secrets: true,
		Help:  "Everything, including passkeys, spaces and favorites. Encrypted with Argon2id and AES-256-GCM when you set a password.",
		Write: writeAPMExport,
	})
}

var apmV1Keys = []string{"entries", "totp_entries", "tokens", "secure_notes", "api_keys", "ssh_keys", "wifi_credentials", "recovery_codes"}

func detectAPM(name string, data []byte) int {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return 0
	}
	if trim[0] != '{' {
		ext := strings.ToLower(filepath.Ext(name))
		if (ext == ".json" || ext == ".apm" || ext == "") && len(data) >= 60 && !isMostlyText(data) {
			return 30
		}
		return 0
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(trim, &probe) != nil {
		return 0
	}
	if f, ok := probe["format"]; ok && strings.Contains(string(f), apmExportFormat) {
		return 100
	}
	if _, ok := probe["apm_export"]; ok {
		return 95
	}
	if _, ok := probe["enc_salt"]; ok {
		if _, ok := probe["data"]; ok {
			return 80
		}
	}
	for _, k := range apmV1Keys {
		if _, ok := probe[k]; ok {
			return 90
		}
	}
	return 0
}

func isMostlyText(b []byte) bool {
	if len(b) > 512 {
		b = b[:512]
	}
	bad := 0
	for _, c := range b {
		if c < 9 || (c > 13 && c < 32) {
			bad++
		}
	}
	return bad*20 < len(b)
}

func parseAPM(name string, data []byte, password string) (*TransferSet, error) {
	trim := bytes.TrimSpace(data)
	set := &TransferSet{Format: "apm", FormatLabel: "APM export", Vendor: "apm"}
	if len(trim) == 0 || trim[0] != '{' {
		plain, err := decryptAPMBlob(data, password)
		if err != nil {
			return nil, err
		}
		set.Encrypted = true
		set.FormatLabel = "APM export (encrypted)"
		trim = bytes.TrimSpace(plain)
	}
	var doc apmExportDoc
	_ = json.Unmarshal(trim, &doc)
	if doc.Format == apmExportFormat && doc.Encrypted {
		blob, err := base64.StdEncoding.DecodeString(doc.Data)
		if err != nil {
			return nil, transferErr(TransferInvalid, "The encrypted export is damaged.")
		}
		plain, err := decryptAPMBlob(blob, password)
		if err != nil {
			return nil, err
		}
		set.Encrypted = true
		set.FormatLabel = "APM export (encrypted)"
		trim = bytes.TrimSpace(plain)
		doc = apmExportDoc{}
		if err := json.Unmarshal(trim, &doc); err != nil {
			return nil, transferErr(TransferInvalid, "The decrypted export is not valid JSON.")
		}
	}
	if doc.Format == apmExportFormat {
		for _, x := range doc.Items {
			it := NewTransferItem(x.Type, x.Title)
			for k, v := range x.Fields {
				it.Fields[k] = v
			}
			it.Space, it.HasSpace, it.Favorite = x.Space, true, x.Favorite
			for _, pk := range x.Passkeys {
				if pk.CredentialID == "" || len(pk.PrivateKey) == 0 {
					it.DropPasskey(pk.RPID, pk.UserName, "The export does not include its private key")
					continue
				}
				pk.CredentialID = NormalizePasskeyCredentialID(pk.CredentialID)
				it.Passkeys = append(it.Passkeys, pk)
			}
			if x.File != nil {
				it.File = &TransferFile{Name: x.File.Name}
				if x.File.Data != "" {
					b, err := base64.StdEncoding.DecodeString(x.File.Data)
					if err != nil {
						it.Problem("The file data is damaged")
					}
					it.File.Data = b
				}
			}
			set.Add(it)
		}
		return set, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trim, &raw); err != nil {
		return nil, transferErr(TransferInvalid, "This APM export is not valid JSON.")
	}
	if _, ok := raw["apm_export"]; ok {
		var old struct {
			Items []struct {
				Type   string         `json:"type"`
				Space  string         `json:"space"`
				Fields map[string]any `json:"fields"`
			} `json:"items"`
		}
		_ = json.Unmarshal(trim, &old)
		for _, x := range old.Items {
			spec, ok := ItemTypeByID(x.Type)
			title := ""
			if ok {
				title = toStringValue(x.Fields[spec.TitleKey])
			}
			it := NewTransferItem(x.Type, title)
			for k, v := range x.Fields {
				it.Fields[k] = v
			}
			it.Space, it.HasSpace = x.Space, true
			set.Add(it)
		}
		set.FormatLabel = "APM export (version 1)"
		return set, nil
	}
	if d, ok := raw["data"]; ok {
		if s, ok2 := raw["enc_salt"]; ok2 {
			var ds, ss string
			_ = json.Unmarshal(d, &ds)
			_ = json.Unmarshal(s, &ss)
			blob, _ := DecodeBase64(ds)
			plain, err := decryptAPMBlob(append([]byte(ss), blob...), password)
			if err != nil {
				return nil, err
			}
			set.Encrypted = true
			if err := json.Unmarshal(bytes.TrimSpace(plain), &raw); err != nil {
				return nil, transferErr(TransferInvalid, "The decrypted export is not valid JSON.")
			}
		}
	}
	// Version 1 used the vault's own collections, so decode them into a vault
	// and collect items the same way a vault export does.
	var probe Vault
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, transferErr(TransferInvalid, "This APM export could not be read: %v", err)
	}
	for _, it := range probe.CollectTransferItems(ExportSelection{Passkeys: true, Files: true}) {
		it.HasSpace = it.Space != ""
		set.Add(it)
	}
	if set.FormatLabel == "APM export" {
		set.FormatLabel = "APM export (version 1)"
	}
	if set.Encrypted {
		set.FormatLabel = "APM export (version 1, encrypted)"
	}
	return set, nil
}

func decryptAPMBlob(blob []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, transferErr(TransferNeedsPassword, "This APM export is encrypted. Enter the password chosen when it was exported.")
	}
	plain, err := DecryptData(blob, password)
	if err != nil {
		return nil, transferErr(TransferWrongPassword, "That password does not open this export.")
	}
	return plain, nil
}

func parseAPMVault(name string, data []byte, password string) (*TransferSet, error) {
	if password == "" {
		return nil, transferErr(TransferNeedsPassword, "This is an APM vault. Enter its master password to read it.")
	}
	v, err := DecryptVault(data, password, 1)
	if err != nil {
		return nil, transferErr(TransferWrongPassword, "That master password does not open this vault.")
	}
	set := &TransferSet{Format: "apm-vault", FormatLabel: "APM vault", Vendor: "apm", Encrypted: true}
	for _, it := range v.CollectTransferItems(ExportSelection{Passkeys: true, Files: true}) {
		set.Add(it)
	}
	return set, nil
}

func writeAPMExport(items []TransferItem, opt ExportOptions) ([]byte, error) {
	doc := apmExportDoc{Format: apmExportFormat, Version: 2, Created: opt.Created.UTC().Format(time.RFC3339), Vault: opt.VaultName, Counts: map[string]int{}}
	for _, it := range items {
		x := apmExportItem{Type: it.Type, Title: it.Title, Space: it.Space, Favorite: it.Favorite, Fields: map[string]any{}, Passkeys: it.Passkeys}
		for k, v := range it.Fields {
			if isEmptyValue(v) {
				continue
			}
			x.Fields[k] = v
		}
		if it.File != nil && len(it.File.Data) > 0 {
			x.File = &apmExportFileT{Name: it.File.Name, Data: base64.StdEncoding.EncodeToString(it.File.Data)}
		}
		doc.Items = append(doc.Items, x)
		doc.Counts[it.Type]++
		doc.Counts["passkeys"] += len(it.Passkeys)
	}
	doc.Counts["items"] = len(items)
	plain, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if opt.Password == "" {
		return append(plain, '\n'), nil
	}
	blob, err := EncryptData(plain, opt.Password)
	if err != nil {
		return nil, err
	}
	env := apmExportDoc{Format: apmExportFormat, Version: 2, Created: doc.Created, Encrypted: true, Cipher: "AES-256-GCM", KDF: "Argon2id", Data: base64.StdEncoding.EncodeToString(blob)}
	out, err := json.MarshalIndent(env, "", "  ")
	return append(out, '\n'), err
}

func isEmptyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []string:
		return len(t) == 0
	case []any:
		return len(t) == 0
	case bool:
		return !t
	}
	rv := reflect.ValueOf(v)
	return (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Map) && rv.Len() == 0
}
