package apm

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

// Bitwarden: the unencrypted JSON export, the password-protected JSON export,
// the zip export (data.json plus attachments) and the CSV export. Passkeys
// come from login.fido2Credentials with their PKCS#8 private keys.

func init() {
	RegisterTransferFormat(TransferFormat{
		ID: "bitwarden", Label: "Bitwarden JSON", Vendor: "bitwarden", Ext: []string{".json", ".zip"},
		Help:   "In Bitwarden choose Tools > Export vault, then .json or .json (Password protected). Passkeys, folders, custom fields and password history come along. Choose .zip to include attachments.",
		Detect: detectBitwardenJSON, Parse: parseBitwardenJSON,
	})
	RegisterTransferFormat(TransferFormat{
		ID: "bitwarden-csv", Label: "Bitwarden CSV", Vendor: "bitwarden", Ext: []string{".csv"},
		Help:   "Bitwarden's CSV export holds logins and notes only, without passkeys. Prefer the .json export.",
		Detect: detectBitwardenCSV, Parse: parseBitwardenCSV,
	})
	RegisterTransferExporter(TransferExporter{
		ID: "bitwarden", Label: "Bitwarden", Vendor: "bitwarden", Ext: "json", Passkeys: true, Encryption: true, Secrets: true,
		Help:  "A Bitwarden .json export with passkeys, folders and one-time codes. Import it in Bitwarden with File > Import data. Set a password for Bitwarden's password-protected format.",
		Write: writeBitwardenExport,
	})
}

// bwText decodes a JSON string, number, boolean or null as text.
type bwText string

func (t *bwText) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*t = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*t = bwText(s)
		return nil
	}
	*t = bwText(string(b))
	return nil
}

func (t bwText) String() string { return strings.TrimSpace(string(t)) }

type bwFolder struct {
	ID   bwText `json:"id"`
	Name bwText `json:"name"`
}

type bwField struct {
	Name     bwText `json:"name"`
	Value    bwText `json:"value"`
	Type     int    `json:"type"`
	LinkedID *int   `json:"linkedId,omitempty"`
}

type bwURI struct {
	URI   bwText `json:"uri"`
	Match *int   `json:"match"`
}

type bwFido2 struct {
	CredentialID    bwText `json:"credentialId"`
	KeyType         bwText `json:"keyType"`
	KeyAlgorithm    bwText `json:"keyAlgorithm"`
	KeyCurve        bwText `json:"keyCurve"`
	KeyValue        bwText `json:"keyValue"`
	RPID            bwText `json:"rpId"`
	UserHandle      bwText `json:"userHandle"`
	UserName        bwText `json:"userName"`
	Counter         bwText `json:"counter"`
	RPName          bwText `json:"rpName"`
	UserDisplayName bwText `json:"userDisplayName"`
	Discoverable    bwText `json:"discoverable"`
	CreationDate    bwText `json:"creationDate"`
}

type bwLogin struct {
	URIs             []bwURI   `json:"uris"`
	Username         bwText    `json:"username"`
	Password         bwText    `json:"password"`
	TOTP             bwText    `json:"totp"`
	Fido2Credentials []bwFido2 `json:"fido2Credentials,omitempty"`
}

type bwCard struct {
	CardholderName bwText `json:"cardholderName"`
	Brand          bwText `json:"brand"`
	Number         bwText `json:"number"`
	ExpMonth       bwText `json:"expMonth"`
	ExpYear        bwText `json:"expYear"`
	Code           bwText `json:"code"`
}

type bwIdentity struct {
	Title          bwText `json:"title"`
	FirstName      bwText `json:"firstName"`
	MiddleName     bwText `json:"middleName"`
	LastName       bwText `json:"lastName"`
	Address1       bwText `json:"address1"`
	Address2       bwText `json:"address2"`
	Address3       bwText `json:"address3"`
	City           bwText `json:"city"`
	State          bwText `json:"state"`
	PostalCode     bwText `json:"postalCode"`
	Country        bwText `json:"country"`
	Company        bwText `json:"company"`
	Email          bwText `json:"email"`
	Phone          bwText `json:"phone"`
	SSN            bwText `json:"ssn"`
	Username       bwText `json:"username"`
	PassportNumber bwText `json:"passportNumber"`
	LicenseNumber  bwText `json:"licenseNumber"`
}

type bwSSHKey struct {
	PrivateKey     bwText `json:"privateKey"`
	PublicKey      bwText `json:"publicKey"`
	KeyFingerprint bwText `json:"keyFingerprint"`
}

type bwHistory struct {
	LastUsedDate bwText `json:"lastUsedDate"`
	Password     bwText `json:"password"`
}

type bwSecureNote struct {
	Type int `json:"type"`
}

type bwItem struct {
	ID              bwText                     `json:"id"`
	OrganizationID  *string                    `json:"organizationId"`
	FolderID        *string                    `json:"folderId"`
	Type            int                        `json:"type"`
	Reprompt        int                        `json:"reprompt"`
	Name            bwText                     `json:"name"`
	Notes           *string                    `json:"notes"`
	Favorite        bool                       `json:"favorite"`
	Fields          []bwField                  `json:"fields,omitempty"`
	Login           *bwLogin                   `json:"login,omitempty"`
	SecureNote      *bwSecureNote              `json:"secureNote,omitempty"`
	Card            *bwCard                    `json:"card,omitempty"`
	Identity        *bwIdentity                `json:"identity,omitempty"`
	SSHKey          *bwSSHKey                  `json:"sshKey,omitempty"`
	BankAccount     map[string]json.RawMessage `json:"bankAccount,omitempty"`
	DriversLicense  map[string]json.RawMessage `json:"driversLicense,omitempty"`
	Passport        map[string]json.RawMessage `json:"passport,omitempty"`
	PasswordHistory []bwHistory                `json:"passwordHistory,omitempty"`
	RevisionDate    string                     `json:"revisionDate,omitempty"`
	CreationDate    string                     `json:"creationDate,omitempty"`
	DeletedDate     *string                    `json:"deletedDate"`
	CollectionIDs   []string                   `json:"collectionIds"`
}

type bwExport struct {
	Encrypted         bool       `json:"encrypted"`
	PasswordProtected bool       `json:"passwordProtected,omitempty"`
	Salt              string     `json:"salt,omitempty"`
	KdfType           *int       `json:"kdfType,omitempty"`
	KdfIterations     *int       `json:"kdfIterations,omitempty"`
	KdfMemory         *int       `json:"kdfMemory,omitempty"`
	KdfParallelism    *int       `json:"kdfParallelism,omitempty"`
	EncKeyValidation  string     `json:"encKeyValidation_DO_NOT_EDIT,omitempty"`
	Data              string     `json:"data,omitempty"`
	Folders           []bwFolder `json:"folders,omitempty"`
	Collections       []bwFolder `json:"collections,omitempty"`
	Items             []bwItem   `json:"items"`
}

func bwZipData(data []byte) (*zip.Reader, []byte) {
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return nil, nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil
	}
	for _, f := range zr.File {
		if f.Name == "data.json" {
			rc, err := f.Open()
			if err != nil {
				return zr, nil
			}
			b, err := io.ReadAll(io.LimitReader(rc, 256<<20))
			rc.Close()
			if err != nil {
				return zr, nil
			}
			return zr, b
		}
	}
	return nil, nil
}

func detectBitwardenJSON(name string, data []byte) int {
	if zr, b := bwZipData(data); zr != nil {
		if b != nil && detectBitwardenJSON("data.json", b) > 0 {
			return 100
		}
		return 0
	}
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 || trim[0] != '{' {
		return 0
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(trim, &probe) != nil {
		return 0
	}
	if _, ok := probe["encKeyValidation_DO_NOT_EDIT"]; ok {
		return 100
	}
	_, hasEnc := probe["encrypted"]
	_, hasItems := probe["items"]
	_, hasFolders := probe["folders"]
	_, hasCollections := probe["collections"]
	if hasItems && hasEnc {
		return 100
	}
	if hasItems && (hasFolders || hasCollections) {
		var items []map[string]json.RawMessage
		if json.Unmarshal(probe["items"], &items) == nil && (len(items) == 0 || items[0]["type"] != nil && items[0]["name"] != nil) {
			return 90
		}
	}
	return 0
}

func parseBitwardenJSON(name string, data []byte, password string) (*TransferSet, error) {
	zr, inner := bwZipData(data)
	if zr != nil {
		if inner == nil {
			return nil, transferErr(TransferInvalid, "The Bitwarden zip has no data.json.")
		}
		data = inner
	}
	var doc bwExport
	if err := json.Unmarshal(bytes.TrimSpace(data), &doc); err != nil {
		return nil, transferErr(TransferInvalid, "This Bitwarden export is not valid JSON: %v", err)
	}
	set := &TransferSet{Format: "bitwarden", FormatLabel: "Bitwarden JSON", Vendor: "bitwarden"}
	if zr != nil {
		set.FormatLabel = "Bitwarden zip"
	}
	if doc.Encrypted {
		if !doc.PasswordProtected {
			return nil, transferErr(TransferAccountEncrypted, "This Bitwarden export is locked to your Bitwarden account and only Bitwarden can open it. Export again and choose .json (Password protected) or .json.")
		}
		if password == "" {
			return nil, transferErr(TransferNeedsPassword, "This is a password-protected Bitwarden export. Enter the file password you set when exporting.")
		}
		plain, err := bwDecryptExport(&doc, password)
		if err != nil {
			return nil, err
		}
		doc = bwExport{}
		if err := json.Unmarshal(bytes.TrimSpace(plain), &doc); err != nil {
			return nil, transferErr(TransferInvalid, "The decrypted Bitwarden export is not valid JSON.")
		}
		set.Encrypted = true
		set.FormatLabel = "Bitwarden (password protected)"
	}
	folders := map[string]string{}
	for _, f := range doc.Folders {
		folders[f.ID.String()] = f.Name.String()
	}
	for _, c := range doc.Collections {
		folders[c.ID.String()] = c.Name.String()
	}
	deleted := 0
	for i := range doc.Items {
		x := &doc.Items[i]
		if x.DeletedDate != nil && strings.TrimSpace(*x.DeletedDate) != "" {
			deleted++
			continue
		}
		folder := ""
		if x.FolderID != nil {
			folder = folders[*x.FolderID]
		}
		if folder == "" {
			for _, c := range x.CollectionIDs {
				if n := folders[c]; n != "" {
					folder = n
					break
				}
			}
		}
		bwAddItem(set, x, folder, zr)
	}
	if deleted > 0 {
		set.Warn("%s in Bitwarden's trash were left out.", plural(deleted, "item"))
	}
	return set, nil
}

func bwNotes(x *bwItem) string {
	if x.Notes == nil {
		return ""
	}
	return strings.TrimSpace(*x.Notes)
}

func bwCustomFields(it *TransferItem, x *bwItem) {
	for _, f := range x.Fields {
		if f.Type == 3 {
			continue
		}
		name := f.Name.String()
		if name == "" {
			name = "Field"
		}
		it.Note(name, f.Value.String())
	}
}

func bwAddItem(set *TransferSet, x *bwItem, folder string, zr *zip.Reader) {
	title := x.Name.String()
	base := func(typ, t string) TransferItem {
		it := NewTransferItem(typ, t)
		it.Folder, it.Favorite = folder, x.Favorite
		if x.Reprompt == 1 {
			it.Warn("Bitwarden asked for the master password before showing this item. APM does not re-prompt.")
		}
		return it
	}
	var idx int
	switch x.Type {
	case 1:
		it := base("password", title)
		l := x.Login
		if l == nil {
			l = &bwLogin{}
		}
		it.Set("username", l.Username.String())
		it.Set("password", l.Password.String())
		urls := []string{}
		for _, u := range l.URIs {
			if s := u.URI.String(); s != "" {
				urls = append(urls, s)
			}
		}
		if len(urls) > 0 {
			it.Set("website", urls[0])
			if len(urls) > 1 {
				it.Set("urls", urls[1:])
			}
		}
		it.Note("", bwNotes(x))
		bwCustomFields(&it, x)
		for _, f := range l.Fido2Credentials {
			bwAddPasskey(&it, f)
		}
		for _, h := range x.PasswordHistory {
			if p := h.Password.String(); p != "" {
				it.History = append(it.History, TransferVersion{Fields: map[string]any{"password": p}, At: ParseTransferTime(h.LastUsedDate.String())})
			}
		}
		idx = set.Add(it)
		if t := l.TOTP.String(); t != "" {
			set.AddTOTP(idx, t)
		}
	case 2:
		it := base("note", title)
		it.Set("content", bwNotes(x))
		bwCustomFields(&it, x)
		idx = set.Add(it)
	case 3:
		it := base("banking", title)
		it.Set("type", "Card")
		if c := x.Card; c != nil {
			it.Set("details", c.Number.String())
			it.Set("cvv", c.Code.String())
			it.Set("expiry", bwExpiry(c.ExpMonth.String(), c.ExpYear.String()))
			it.Note("Cardholder", c.CardholderName.String())
			it.Note("Brand", c.Brand.String())
		}
		it.Note("", bwNotes(x))
		bwCustomFields(&it, x)
		idx = set.Add(it)
	case 4:
		idx = bwAddIdentity(set, x, folder, base)
	case 5:
		it := base("ssh_key", title)
		if k := x.SSHKey; k != nil {
			it.Set("private_key", k.PrivateKey.String())
			it.Note("Public key", k.PublicKey.String())
			it.Note("Fingerprint", k.KeyFingerprint.String())
		}
		it.Note("", bwNotes(x))
		bwCustomFields(&it, x)
		idx = set.Add(it)
	case 6:
		it := base("banking", title)
		m := bwMap(x.BankAccount)
		number := bwPick(m, "iban", "accountNumber", "number")
		if bwPick(m, "iban") != "" {
			it.Set("type", "IBAN")
		} else {
			it.Set("type", "SWIFT")
		}
		it.Set("details", number)
		bwLeftovers(&it, m, "iban", "accountNumber", "number")
		it.Note("", bwNotes(x))
		bwCustomFields(&it, x)
		idx = set.Add(it)
	case 7, 8:
		m := bwMap(x.DriversLicense)
		kind := "Driver's License"
		numKeys := []string{"licenseNumber", "number", "documentNumber"}
		if x.Type == 8 {
			m = bwMap(x.Passport)
			kind = "Passport"
			numKeys = []string{"passportNumber", "number", "documentNumber"}
		}
		it := base("govid", title)
		it.Set("type", kind)
		it.Set("id_number", bwPick(m, numKeys...))
		it.Set("expiry", bwDate(bwPick(m, "expirationDate", "expiryDate", "expires")))
		bwLeftovers(&it, m, append(numKeys, "expirationDate", "expiryDate", "expires")...)
		it.Note("", bwNotes(x))
		bwCustomFields(&it, x)
		idx = set.Add(it)
	default:
		it := base("note", title)
		it.Problem("Bitwarden item type %d is not supported", x.Type)
		set.Add(it)
		return
	}
	if zr != nil {
		bwAttachments(set, idx, x, folder, zr)
	}
}

func bwAddPasskey(it *TransferItem, f bwFido2) {
	rp, user := f.RPID.String(), f.UserName.String()
	if alg := strings.ToUpper(f.KeyAlgorithm.String()); alg != "" && alg != "ECDSA" {
		it.DropPasskey(rp, user, "It uses "+f.KeyAlgorithm.String()+". APM passkeys use ES256 (P-256)")
		return
	}
	if curve := strings.ToUpper(f.KeyCurve.String()); curve != "" && curve != "P-256" {
		it.DropPasskey(rp, user, "It uses the "+f.KeyCurve.String()+" curve. APM passkeys use P-256")
		return
	}
	der, err := DecodeFlexibleBase64(f.KeyValue.String())
	if err != nil || len(der) == 0 {
		it.DropPasskey(rp, user, "The export does not include a readable private key")
		return
	}
	key, err := PasskeyKeyFromPKCS8(der)
	if err != nil {
		msg := err.Error()
		it.DropPasskey(rp, user, strings.ToUpper(msg[:1])+msg[1:])
		return
	}
	cred, err := CredentialIDBytes(f.CredentialID.String())
	if err != nil || len(cred) == 0 {
		it.DropPasskey(rp, user, "Its credential ID is not readable")
		return
	}
	count, _ := strconv.ParseInt(f.Counter.String(), 10, 64)
	it.AddPasskey(ImportedPasskey{
		RPID:            rp,
		UserName:        user,
		UserDisplayName: f.UserDisplayName.String(),
		UserHandle:      f.UserHandle.String(),
		CredentialID:    base64.RawURLEncoding.EncodeToString(cred),
		Key:             key,
		SignCount:       count,
		Created:         ParseTransferTime(f.CreationDate.String()),
	})
}

func bwAddIdentity(set *TransferSet, x *bwItem, folder string, base func(typ, t string) TransferItem) int {
	id := x.Identity
	if id == nil {
		id = &bwIdentity{}
	}
	title := x.Name.String()
	full := strings.Join(strings.Fields(strings.Join([]string{id.FirstName.String(), id.MiddleName.String(), id.LastName.String()}, " ")), " ")
	it := base("contact", title)
	if it.Title == "" {
		it.Title = full
	}
	it.Set("phone", id.Phone.String())
	it.Set("email", id.Email.String())
	lines := []string{}
	for _, l := range []bwText{id.Address1, id.Address2, id.Address3} {
		if s := l.String(); s != "" {
			lines = append(lines, s)
		}
	}
	cityLine := strings.Join(strings.Fields(strings.Join([]string{id.City.String(), id.State.String(), id.PostalCode.String()}, " ")), " ")
	if cityLine != "" {
		lines = append(lines, cityLine)
	}
	if c := id.Country.String(); c != "" {
		lines = append(lines, c)
	}
	it.Set("address", strings.Join(lines, "\n"))
	if full != "" && !strings.EqualFold(full, it.Title) {
		it.Note("Full name", full)
	}
	it.Note("Title", id.Title.String())
	it.Note("Company", id.Company.String())
	it.Note("Username", id.Username.String())
	it.Note("", bwNotes(x))
	bwCustomFields(&it, x)
	idx := set.Add(it)
	owner := full
	if owner == "" {
		owner = it.Title
	}
	for _, doc := range []struct {
		num  string
		kind string
		word string
	}{{id.SSN.String(), "National ID", "national ID"}, {id.PassportNumber.String(), "Passport", "passport"}, {id.LicenseNumber.String(), "Driver's License", "driver's license"}} {
		if doc.num == "" {
			continue
		}
		g := base("govid", strings.TrimSpace(owner+" "+doc.word))
		g.Set("type", doc.kind)
		g.Set("id_number", doc.num)
		g.Link = idx
		set.Add(g)
	}
	return idx
}

func bwAttachments(set *TransferSet, parent int, x *bwItem, folder string, zr *zip.Reader) {
	prefix := "attachments/" + x.ID.String() + "/"
	if x.ID.String() == "" {
		return
	}
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) || strings.HasSuffix(f.Name, "/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, 256<<20))
		rc.Close()
		if err != nil {
			continue
		}
		file := path.Base(f.Name)
		doc := NewTransferItem("document", set.Items[parent].Title+" · "+file)
		doc.Folder, doc.Link = folder, parent
		doc.File = &TransferFile{Name: file, Data: b}
		set.Add(doc)
	}
}

func bwMap(m map[string]json.RawMessage) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		var t bwText
		if json.Unmarshal(v, &t) == nil && t.String() != "" {
			out[k] = t.String()
		}
	}
	return out
}

func bwPick(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func bwLeftovers(it *TransferItem, m map[string]string, used ...string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !containsString(used, k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		it.Note(splitCamelCase(k), m[k])
	}
}

func bwDate(s string) string {
	if t := ParseTransferTime(s); !t.IsZero() {
		return t.Format("2006-01-02")
	}
	return s
}

func bwExpiry(month, year string) string {
	month, year = strings.TrimSpace(month), strings.TrimSpace(year)
	if month == "" && year == "" {
		return ""
	}
	if len(month) == 1 {
		month = "0" + month
	}
	if len(year) == 4 {
		year = year[2:]
	}
	return month + "/" + year
}

// Password-protected exports

type bwKeys struct {
	enc []byte
	mac []byte
}

func bwDeriveKeys(password, salt string, kdfType, iterations, memory, parallelism int) (bwKeys, error) {
	var k []byte
	var err error
	switch kdfType {
	case 0:
		if iterations < 1 || iterations > 10_000_000 {
			return bwKeys{}, transferErr(TransferInvalid, "The export's PBKDF2 iteration count (%d) is not valid.", iterations)
		}
		k, err = pbkdf2.Key(sha256.New, password, []byte(salt), iterations, 32)
		if err != nil {
			return bwKeys{}, err
		}
	case 1:
		if iterations < 1 || iterations > 64 || memory < 1 || memory > 4096 || parallelism < 1 || parallelism > 64 {
			return bwKeys{}, transferErr(TransferInvalid, "The export's Argon2id settings are not valid.")
		}
		s := sha256.Sum256([]byte(salt))
		k = argon2.IDKey([]byte(password), s[:], uint32(iterations), uint32(memory*1024), uint8(parallelism), 32)
	default:
		return bwKeys{}, transferErr(TransferUnsupported, "This Bitwarden export uses an unknown key derivation (%d).", kdfType)
	}
	enc, err := hkdf.Expand(sha256.New, k, "enc", 32)
	if err != nil {
		return bwKeys{}, err
	}
	mac, err := hkdf.Expand(sha256.New, k, "mac", 32)
	if err != nil {
		return bwKeys{}, err
	}
	return bwKeys{enc: enc, mac: mac}, nil
}

var errBWMac = errors.New("mac mismatch")

func bwDecryptString(s string, keys bwKeys) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "2.") {
		return nil, errors.New("unsupported encryption type")
	}
	parts := strings.Split(s[2:], "|")
	if len(parts) != 3 {
		return nil, errors.New("malformed encrypted string")
	}
	iv, err1 := base64.StdEncoding.DecodeString(parts[0])
	ct, err2 := base64.StdEncoding.DecodeString(parts[1])
	mac, err3 := base64.StdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 16 || len(ct) == 0 || len(ct)%16 != 0 {
		return nil, errors.New("malformed encrypted string")
	}
	h := hmac.New(sha256.New, keys.mac)
	h.Write(iv)
	h.Write(ct)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, errBWMac
	}
	block, err := aes.NewCipher(keys.enc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > 16 || pad > len(out) {
		return nil, errors.New("bad padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("bad padding")
		}
	}
	return out[:len(out)-pad], nil
}

func bwEncryptString(plain []byte, keys bwKeys) (string, error) {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := 16 - len(plain)%16
	buf := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, err := aes.NewCipher(keys.enc)
	if err != nil {
		return "", err
	}
	ct := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, buf)
	h := hmac.New(sha256.New, keys.mac)
	h.Write(iv)
	h.Write(ct)
	enc := base64.StdEncoding.EncodeToString
	return "2." + enc(iv) + "|" + enc(ct) + "|" + enc(h.Sum(nil)), nil
}

func bwDecryptExport(doc *bwExport, password string) ([]byte, error) {
	kdf, iter, mem, par := 0, 600000, 64, 4
	if doc.KdfType != nil {
		kdf = *doc.KdfType
	}
	if doc.KdfIterations != nil {
		iter = *doc.KdfIterations
	}
	if doc.KdfMemory != nil {
		mem = *doc.KdfMemory
	}
	if doc.KdfParallelism != nil {
		par = *doc.KdfParallelism
	}
	keys, err := bwDeriveKeys(password, doc.Salt, kdf, iter, mem, par)
	if err != nil {
		return nil, err
	}
	if _, err := bwDecryptString(doc.EncKeyValidation, keys); err != nil {
		if errors.Is(err, errBWMac) {
			return nil, transferErr(TransferWrongPassword, "That password does not open this Bitwarden export.")
		}
		return nil, transferErr(TransferInvalid, "This Bitwarden export is damaged.")
	}
	plain, err := bwDecryptString(doc.Data, keys)
	if err != nil {
		return nil, transferErr(TransferInvalid, "This Bitwarden export is damaged.")
	}
	return plain, nil
}

// CSV

func detectBitwardenCSV(name string, data []byte) int {
	c := NewCSVColumns(csvHead(data))
	if c.Has("type", "name") && (c.Has("login_uri") || c.Has("login_password") || c.Has("login_username")) {
		return 90
	}
	return 0
}

func parseBitwardenCSV(name string, data []byte, password string) (*TransferSet, error) {
	head, rows, err := ReadCSVTable(data)
	if err != nil {
		return nil, err
	}
	c := NewCSVColumns(head)
	set := &TransferSet{Format: "bitwarden-csv", FormatLabel: "Bitwarden CSV", Vendor: "bitwarden"}
	for _, row := range rows {
		typ := strings.ToLower(c.Get(row, "type"))
		title := c.Get(row, "name")
		var it TransferItem
		switch typ {
		case "note":
			it = NewTransferItem("note", title)
			it.Set("content", c.Get(row, "notes"))
		case "login", "":
			it = NewTransferItem("password", title)
			it.Set("username", c.Get(row, "login_username"))
			it.Set("password", c.Get(row, "login_password"))
			urls := bwSplitURIs(c.Get(row, "login_uri"))
			if len(urls) > 0 {
				it.Set("website", urls[0])
				if len(urls) > 1 {
					it.Set("urls", urls[1:])
				}
			}
			it.Note("", c.Get(row, "notes"))
		default:
			it = NewTransferItem("note", title)
			it.Problem("Bitwarden CSV type %q is not supported", typ)
		}
		it.Folder = c.Get(row, "folder", "collections")
		if strings.Contains(it.Folder, ",") && c.Has("collections") {
			it.Folder = strings.TrimSpace(strings.Split(it.Folder, ",")[0])
		}
		f := c.Get(row, "favorite")
		it.Favorite = f == "1" || strings.EqualFold(f, "true")
		for _, line := range strings.Split(c.Get(row, "fields"), "\n") {
			if k, v, ok := strings.Cut(line, ": "); ok {
				it.Note(strings.TrimSpace(k), v)
			} else {
				it.Note("", line)
			}
		}
		idx := set.Add(it)
		if t := c.Get(row, "login_totp"); t != "" && it.Type == "password" {
			set.AddTOTP(idx, t)
		}
	}
	return set, nil
}

func bwSplitURIs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	r := csv.NewReader(strings.NewReader(s))
	r.LazyQuotes = true
	rec, err := r.Read()
	if err != nil {
		rec = strings.Split(s, ",")
	}
	out := []string{}
	for _, u := range rec {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// Export

type bwOutFido2 struct {
	CredentialID    string `json:"credentialId"`
	KeyType         string `json:"keyType"`
	KeyAlgorithm    string `json:"keyAlgorithm"`
	KeyCurve        string `json:"keyCurve"`
	KeyValue        string `json:"keyValue"`
	RPID            string `json:"rpId"`
	UserHandle      string `json:"userHandle"`
	UserName        string `json:"userName"`
	Counter         string `json:"counter"`
	RPName          string `json:"rpName"`
	UserDisplayName string `json:"userDisplayName"`
	Discoverable    string `json:"discoverable"`
	CreationDate    string `json:"creationDate"`
}

type bwOutURI struct {
	Match *int   `json:"match"`
	URI   string `json:"uri"`
}

type bwOutLogin struct {
	Fido2Credentials []bwOutFido2 `json:"fido2Credentials"`
	URIs             []bwOutURI   `json:"uris"`
	Username         *string      `json:"username"`
	Password         *string      `json:"password"`
	TOTP             *string      `json:"totp"`
}

type bwOutCard struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

type bwOutIdentity struct {
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

type bwOutSSH struct {
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}

type bwOutItem struct {
	ID              string         `json:"id"`
	OrganizationID  *string        `json:"organizationId"`
	FolderID        *string        `json:"folderId"`
	Type            int            `json:"type"`
	Reprompt        int            `json:"reprompt"`
	Name            string         `json:"name"`
	Notes           *string        `json:"notes"`
	Favorite        bool           `json:"favorite"`
	Login           *bwOutLogin    `json:"login,omitempty"`
	SecureNote      *bwSecureNote  `json:"secureNote,omitempty"`
	Card            *bwOutCard     `json:"card,omitempty"`
	Identity        *bwOutIdentity `json:"identity,omitempty"`
	SSHKey          *bwOutSSH      `json:"sshKey,omitempty"`
	CollectionIDs   []string       `json:"collectionIds"`
	PasswordHistory []bwHistory    `json:"passwordHistory"`
	RevisionDate    string         `json:"revisionDate"`
	CreationDate    string         `json:"creationDate"`
	DeletedDate     *string        `json:"deletedDate"`
}

type bwOutFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bwOutExport struct {
	Encrypted bool          `json:"encrypted"`
	Folders   []bwOutFolder `json:"folders"`
	Items     []bwOutItem   `json:"items"`
}

type bwOutProtected struct {
	Encrypted         bool   `json:"encrypted"`
	PasswordProtected bool   `json:"passwordProtected"`
	Salt              string `json:"salt"`
	KdfType           int    `json:"kdfType"`
	KdfIterations     int    `json:"kdfIterations"`
	EncKeyValidation  string `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              string `json:"data"`
}

func strPtr(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func bwOutPasskeys(list []Passkey) []bwOutFido2 {
	out := []bwOutFido2{}
	for _, pk := range list {
		der, err := PasskeyPKCS8(pk)
		if err != nil {
			continue
		}
		created := PasskeyCreated(pk)
		if created.IsZero() {
			created = time.Now()
		}
		display := pk.UserDisplayName
		if display == "" {
			display = pk.UserName
		}
		out = append(out, bwOutFido2{
			CredentialID:    BitwardenCredentialID(pk.CredentialID),
			KeyType:         "public-key",
			KeyAlgorithm:    "ECDSA",
			KeyCurve:        "P-256",
			KeyValue:        base64.RawURLEncoding.EncodeToString(der),
			RPID:            pk.RPID,
			UserHandle:      NormalizePasskeyCredentialID(pk.UserHandle),
			UserName:        pk.UserName,
			Counter:         strconv.FormatInt(pk.SignCount, 10),
			RPName:          pk.RPID,
			UserDisplayName: display,
			Discoverable:    "true",
			CreationDate:    created.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}
	return out
}

func bwSSHPublic(privateKey string) (string, string) {
	key, err := ssh.ParseRawPrivateKey([]byte(privateKey))
	if err != nil {
		return "", ""
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return "", ""
	}
	pub := signer.PublicKey()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), ssh.FingerprintSHA256(pub)
}

func splitName(full string) (string, string) {
	parts := strings.Fields(full)
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], ""
	}
	return strings.Join(parts[:len(parts)-1], " "), parts[len(parts)-1]
}

func writeBitwardenExport(items []TransferItem, opt ExportOptions) ([]byte, error) {
	now := opt.Created
	if now.IsZero() {
		now = time.Now()
	}
	stamp := now.UTC().Format("2006-01-02T15:04:05.000Z")
	doc := bwOutExport{Folders: []bwOutFolder{}, Items: []bwOutItem{}}
	folderIDs := map[string]string{}
	folderFor := func(space string) *string {
		space = strings.TrimSpace(space)
		if space == "" || strings.EqualFold(space, "default") {
			return nil
		}
		key := strings.ToLower(space)
		id, ok := folderIDs[key]
		if !ok {
			id = newUUID()
			folderIDs[key] = id
			doc.Folders = append(doc.Folders, bwOutFolder{ID: id, Name: space})
		}
		return &id
	}
	newItem := func(it *TransferItem, typ int) bwOutItem {
		return bwOutItem{ID: newUUID(), FolderID: folderFor(it.Space), Type: typ, Name: it.Title, Favorite: it.Favorite, PasswordHistory: nil, RevisionDate: stamp, CreationDate: stamp}
	}
	byTitle := map[string]int{}
	byHost := map[string]int{}
	var totps []*TransferItem
	for i := range items {
		it := &items[i]
		switch it.Type {
		case "totp":
			totps = append(totps, it)
		case "password":
			x := newItem(it, 1)
			l := &bwOutLogin{Fido2Credentials: bwOutPasskeys(it.Passkeys), URIs: []bwOutURI{}, Username: strPtr(it.Get("username")), Password: strPtr(it.Get("password"))}
			urls := []string{}
			if w := it.Get("website"); w != "" {
				urls = append(urls, w)
			}
			urls = append(urls, toStringList(it.Fields["urls"])...)
			for _, u := range urls {
				l.URIs = append(l.URIs, bwOutURI{URI: bwURIWithScheme(u)})
			}
			x.Login = l
			x.Notes = strPtr(it.Get("notes"))
			doc.Items = append(doc.Items, x)
			n := len(doc.Items) - 1
			byTitle[strings.ToLower(it.Title)+"\x00"+spaceKey(it.Space)] = n
			for _, u := range urls {
				if h := normalizeDomain(u); h != "" {
					if _, ok := byHost[h]; !ok {
						byHost[h] = n
					}
				}
			}
		case "note":
			x := newItem(it, 2)
			x.SecureNote = &bwSecureNote{Type: 0}
			x.Notes = strPtr(it.Get("content"))
			doc.Items = append(doc.Items, x)
		case "banking":
			if !strings.EqualFold(it.Get("type"), "Card") && it.Get("type") != "" {
				doc.Items = append(doc.Items, bwNoteItem(it, newItem(it, 2)))
				continue
			}
			x := newItem(it, 3)
			month, year := "", ""
			if m, y, ok := strings.Cut(it.Get("expiry"), "/"); ok {
				month, year = strings.TrimLeft(strings.TrimSpace(m), "0"), strings.TrimSpace(y)
				if len(year) == 2 {
					year = "20" + year
				}
			}
			x.Card = &bwOutCard{Number: strPtr(it.Get("details")), Code: strPtr(it.Get("cvv")), ExpMonth: strPtr(month), ExpYear: strPtr(year)}
			x.Notes = strPtr(otherFields(it, "type", "details", "cvv", "expiry"))
			doc.Items = append(doc.Items, x)
		case "contact":
			x := newItem(it, 4)
			first, last := splitName(it.Title)
			x.Identity = &bwOutIdentity{FirstName: strPtr(first), LastName: strPtr(last), Email: strPtr(it.Get("email")), Phone: strPtr(it.Get("phone")), Address1: strPtr(it.Get("address"))}
			x.Notes = strPtr(otherFields(it, "email", "phone", "address"))
			doc.Items = append(doc.Items, x)
		case "ssh_key":
			x := newItem(it, 5)
			priv := it.Get("private_key")
			pub, fp := bwSSHPublic(priv)
			x.SSHKey = &bwOutSSH{PrivateKey: priv, PublicKey: pub, KeyFingerprint: fp}
			doc.Items = append(doc.Items, x)
		default:
			doc.Items = append(doc.Items, bwNoteItem(it, newItem(it, 2)))
		}
	}
	for _, t := range totps {
		secret := t.Get("secret")
		n, ok := byTitle[strings.ToLower(t.Title)+"\x00"+spaceKey(t.Space)]
		if !ok {
			if h := normalizeDomain(t.Get("domain")); h != "" {
				n, ok = byHost[h]
			}
		}
		if ok && doc.Items[n].Login != nil && doc.Items[n].Login.TOTP == nil {
			doc.Items[n].Login.TOTP = strPtr(secret)
			continue
		}
		x := newItem(t, 1)
		x.Login = &bwOutLogin{Fido2Credentials: []bwOutFido2{}, URIs: []bwOutURI{}, TOTP: strPtr(secret)}
		if d := t.Get("domain"); d != "" {
			x.Login.URIs = append(x.Login.URIs, bwOutURI{URI: bwURIWithScheme(d)})
		}
		doc.Items = append(doc.Items, x)
	}
	plain, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if opt.Password == "" {
		return plain, nil
	}
	return bwProtect(plain, opt.Password, 600000)
}

func bwProtect(plain []byte, password string, iterations int) ([]byte, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	salt := base64.StdEncoding.EncodeToString(raw)
	keys, err := bwDeriveKeys(password, salt, 0, iterations, 0, 0)
	if err != nil {
		return nil, err
	}
	validation, err := bwEncryptString([]byte(newUUID()), keys)
	if err != nil {
		return nil, err
	}
	data, err := bwEncryptString(plain, keys)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(bwOutProtected{Encrypted: true, PasswordProtected: true, Salt: salt, KdfType: 0, KdfIterations: iterations, EncKeyValidation: validation, Data: data}, "", "  ")
}

func bwURIWithScheme(u string) string {
	u = strings.TrimSpace(u)
	if u == "" || strings.Contains(u, "://") {
		return u
	}
	return "https://" + u
}

func bwNoteItem(it *TransferItem, x bwOutItem) bwOutItem {
	x.Type = 2
	x.SecureNote = &bwSecureNote{Type: 0}
	lines := []string{"APM " + strings.ToLower(TypeLabel(it.Type))}
	if s := primarySecret(it); s != "" {
		spec, _ := ItemTypeByID(it.Type)
		lines = append(lines, fmt.Sprintf("%s: %s", FieldLabel(it.Type, spec.Secret), s))
	}
	if o := otherFields(it); o != "" {
		lines = append(lines, o)
	}
	x.Notes = strPtr(strings.Join(lines, "\n"))
	return x
}
