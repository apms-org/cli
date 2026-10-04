package apm

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Built with Python hashlib, a hand-rolled HKDF-Expand and openssl enc, not
// with this package, so it checks the crypto against an independent build.
const bwVectorPassword = "correct horse battery"
const bwVectorKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCqi8nsDZYzfedqU8GIVhhviOTAJ7-9FqUSMr9axoFp2hRANCAARobuL9Kebih4iu1l7uoEubtN7JyUqEIuNZddHc5kcxxjnjlnwvpKgmXytK3BaZwtgMD_iPzG9R3J6Aa15Y_0Ie"
const bwVector = `{"encrypted": true, "passwordProtected": true, "salt": "q0jxBnL2xR3TmXe8sP1Zkg==", "kdfType": 0, "kdfIterations": 5000, "encKeyValidation_DO_NOT_EDIT": "2.AAECAwQFBgcICQoLDA0ODw==|bYZZcn4Xb3yrbaTIvAHTwhZM3DNnAI09eR17Bfp48xGiF3AGBc2LwH2wB4J78lmZ|DQ8bIM9seX42qbboUOVSWd0etMGHc6A2nL7Qb2nTHeA=", "data": "2.Dw4NDAsKCQgHBgUEAwIBAA==|IkqBPuwXsL2++N4rLy/8RewJqCVK3vIVrlFwBwSYlpU/c3XvafDQNUm9TlLC2a4rcPizpEqFN0lgSLyDmYASCllNVLmcEnqK3WNQChqSOolwRfqEjbHLbjZJ4VnF1UowhGOx8J21km1pYQvfWb3Dtd7Nzq+xXUvCHk8ZalGVkgM3EhX73C9nG6fh24XCGksDboilAqjp2F+ufAYVFvFrrh6b5Zj5h6h8N7peC4N1sXekP09vPVkACVd4u6vhLu+BFhiNMvbeLjF9laezH/WnfdKoS0hxEUKJBJJykQKVWL7GdtqNqtvR1ucnpNTjebbNf0AAClh1hG/+EQ2Ifijep9JPrDguUQLdK0Wp8hSfOnXfAn/WfCp2WobpK3O7twZu+MXF2754fflmBg9IYErD5zLUyJZgLqvYErna9AQkw8h/SpAnO2FyJsw7Tt4WId5AfiDTOgnjWKkCJ0WFvkEpZeRPeqnXaoj/ZO8vqcOmPWOIIc8IvY7HZnn/8KG8dTXKdUSJ9ZwV9NmlP/buMEf0EGgAbbhb7Rfi7r7cDcTZF4Z9r+Zz5UQiTrL2uOoWdHQEuoFNNboaF0mfsGHNRd/bwVAumD3SEtN8IxVFQ2ee0jWy54Oo70eknpaGRKnWdthbigciJ3YrygcPfZr195PSGoAvUIJLM6okO9fZ3KYZQ0mLXhQhCMpn/PT+A+gc/eNS02h4SpLLkV7PUaTlx7Rio91Pss1B33IrQTAZ30mGjbom/PwLJZE2zCNyahCVL/Mu7bxZvz093O2lq6KIRPsY3fJYQb1lxxzOA6tZ3l9Cub79jPXfjra6CIRXolG+pfZsUiF1OHzUgLsMutpgT1ptakOSUH826+qbZ8iRWUmb35iHaLET61X+MHel39Je6fQUKuVfsacYWjFV2r5E74WwcdWzQ2Byazyywz1HQ0n/Br/eZ8YRduCDT7IAAfDhgCB7XanJv7J5THFdPr9p4lYT72pu1DQsLFzR4pKGJpNQrkjzxVh2IsVPEefgaH84LuH6j6MzKJ9oK0nVKxCjD0i29BCOdxTXW7MP0biOCvLYM5RyzKTfr7HA+YQZhWUVMW99OkDnIogLNsY3Q7kKGbMkeuDifm3WJV2pqq1OpGA/37zW22wTgDyyLS4WAXgzgE7CHqOPOgLM8/fV2uh30IgC0AapvNKQOR8cZnYD+FAYboCEQMuz51E8kBRd5j6xGaNe1WAIfAcECOKwxEFr5d5UCcgYLcmq/7qx+PCKoYksm+UycsWY+nurD2WFGEFEk6xu6rl+4Dq332z5uCrWxiFkC/gFhp2n39KliuqHGj6yCsQvKUjR8a15m8pclF0M0N3w4w4MROI0DFLLGvwgLIUgOV61UYknnIZ6rJE996yDnaXfsjsQq6AJhTJEoIKL/sstV6xuIcU8QyTkBp2RMFgl0iADSoIURdZw6lYaTe8U/P0=|3hcVtk9fYjGO+B8uV4JlWboJcIpZnvMpprHmrxaAf6A="}`

type bwTestKey struct {
	priv  *ecdsa.PrivateKey
	value string
}

func newBWTestKey(t *testing.T) bwTestKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return bwTestKey{priv: priv, value: base64.RawURLEncoding.EncodeToString(der)}
}

func checkPasskeySigns(t *testing.T, pk Passkey, pub *ecdsa.PublicKey) {
	t.Helper()
	priv, err := passkeyECDSA(pk.PrivateKey)
	if err != nil {
		t.Fatalf("stored key: %v", err)
	}
	sum := sha256.Sum256([]byte("challenge"))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatalf("passkey for %s does not verify with the original public key", pk.RPID)
	}
}

func bwTestExport(t *testing.T, k1, k2 bwTestKey) []byte {
	t.Helper()
	doc := map[string]any{
		"encrypted": false,
		"folders":   []any{map[string]any{"id": "f-work", "name": "Work"}},
		"items": []any{
			map[string]any{"id": "1", "type": 1, "name": "GitHub", "favorite": true, "folderId": "f-work", "reprompt": 1, "notes": "main account",
				"fields": []any{map[string]any{"name": "Recovery email", "value": "r@example.com", "type": 0}, map[string]any{"name": "PIN", "value": "4321", "type": 1}, map[string]any{"name": null(), "value": null(), "type": 3, "linkedId": 100}},
				"login": map[string]any{
					"uris":     []any{map[string]any{"uri": "https://github.com/login", "match": nil}, map[string]any{"uri": "https://gist.github.com", "match": nil}},
					"username": "octo", "password": "new-pass", "totp": "JBSWY3DPEHPK3PXP",
					"fido2Credentials": []any{map[string]any{"credentialId": "2b3f1c0e-7a9d-4e2b-9c11-0f6a8d3e5b27", "keyType": "public-key", "keyAlgorithm": "ECDSA", "keyCurve": "P-256", "keyValue": k1.value, "rpId": "github.com", "userHandle": "dXNlci0x", "userName": "octo", "counter": "7", "rpName": "GitHub", "userDisplayName": "Octo Cat", "discoverable": "true", "creationDate": "2025-03-01T10:00:00.000Z"}},
				},
				"passwordHistory": []any{map[string]any{"lastUsedDate": "2024-01-01T00:00:00.000Z", "password": "old-1"}, map[string]any{"lastUsedDate": "2024-06-01T00:00:00.000Z", "password": "old-2"}},
			},
			map[string]any{"id": "2", "type": 1, "name": "Passkey only", "login": map[string]any{"uris": []any{},
				"fido2Credentials": []any{
					map[string]any{"credentialId": "b64." + base64.RawURLEncoding.EncodeToString([]byte("a-longer-credential-id-32-bytes!")), "keyValue": k2.value, "rpId": "webauthn.io", "userName": "w", "counter": "0"},
					map[string]any{"credentialId": "0f0f0f0f-0000-4000-8000-000000000001", "keyAlgorithm": "EdDSA", "keyValue": "AAAA", "rpId": "bad.example", "userName": "x"},
				}}},
			map[string]any{"id": "3", "type": 1, "name": "Steam", "login": map[string]any{"username": "s", "password": "p", "totp": "steam://ABCDEF"}},
			map[string]any{"id": "4", "type": 1, "name": "Otp link", "login": map[string]any{"username": "u", "password": "p", "totp": "otpauth://totp/Acme:u?secret=JBSWY3DPEHPK3PXP&issuer=Acme"}},
			map[string]any{"id": "5", "type": 2, "name": "Door codes", "notes": "front 1234", "secureNote": map[string]any{"type": 0}, "fields": []any{map[string]any{"name": "Back", "value": "5678", "type": 1}}},
			map[string]any{"id": "6", "type": 3, "name": "Visa", "card": map[string]any{"cardholderName": "A B", "brand": "Visa", "number": "4111111111111111", "expMonth": "3", "expYear": "2029", "code": "123"}},
			map[string]any{"id": "7", "type": 4, "name": "Me", "identity": map[string]any{"firstName": "Ada", "lastName": "Lovelace", "phone": "555", "email": "ada@example.com", "address1": "1 Road", "city": "London", "postalCode": "N1", "country": "GB", "ssn": "123-45-6789", "passportNumber": "P123", "company": "Engines"}},
			map[string]any{"id": "8", "type": 5, "name": "Deploy key", "sshKey": map[string]any{"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "publicKey": "ssh-ed25519 AAAA", "keyFingerprint": "SHA256:x"}},
			map[string]any{"id": "9", "type": 1, "name": "Trashed", "login": map[string]any{"username": "t", "password": "t"}, "deletedDate": "2025-01-01T00:00:00.000Z"},
			map[string]any{"id": "10", "type": 1, "name": "GitHub", "folderId": "f-work", "login": map[string]any{"username": "octo2", "password": "other"}},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func null() any { return nil }

func bwFind(set *TransferSet, typ, title string) *TransferItem {
	for i := range set.Items {
		if set.Items[i].Type == typ && set.Items[i].Title == title {
			return &set.Items[i]
		}
	}
	return nil
}

func TestBitwardenJSONImport(t *testing.T) {
	k1, k2 := newBWTestKey(t), newBWTestKey(t)
	set, err := ParseTransfer("bitwarden_export.json", bwTestExport(t, k1, k2), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Format != "bitwarden" || set.Encrypted {
		t.Fatalf("format %q encrypted %v", set.Format, set.Encrypted)
	}
	gh := bwFind(set, "password", "GitHub")
	if gh == nil {
		t.Fatal("GitHub login missing")
	}
	if gh.Get("username") != "octo" || gh.Get("password") != "new-pass" || gh.Get("website") != "https://github.com/login" || gh.Folder != "Work" || !gh.Favorite {
		t.Fatalf("login fields wrong: %+v", gh.Fields)
	}
	if urls := toStringList(gh.Fields["urls"]); len(urls) != 1 || urls[0] != "https://gist.github.com" {
		t.Fatalf("urls %v", urls)
	}
	notes := gh.Get("notes")
	for _, want := range []string{"main account", "Recovery email: r@example.com", "PIN: 4321"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("notes %q missing %q", notes, want)
		}
	}
	if len(gh.Warnings) != 1 {
		t.Fatalf("reprompt warning: %v", gh.Warnings)
	}
	if len(gh.Passkeys) != 1 {
		t.Fatalf("passkeys %d dropped %v", len(gh.Passkeys), gh.Dropped)
	}
	pk := gh.Passkeys[0]
	raw, _ := hex.DecodeString("2b3f1c0e7a9d4e2b9c110f6a8d3e5b27")
	if pk.CredentialID != base64.RawURLEncoding.EncodeToString(raw) || pk.RPID != "github.com" || pk.SignCount != 7 || pk.UserHandle != "dXNlci0x" || pk.UserDisplayName != "Octo Cat" {
		t.Fatalf("passkey %+v", pk)
	}
	checkPasskeySigns(t, pk, &k1.priv.PublicKey)
	if len(gh.History) != 2 {
		t.Fatalf("history %v", gh.History)
	}

	only := bwFind(set, "password", "Passkey only")
	if only == nil || len(only.Passkeys) != 1 || len(only.Dropped) != 1 || len(only.Problems) != 0 {
		t.Fatalf("passkey-only login: %+v", only)
	}
	if only.Passkeys[0].CredentialID != base64.RawURLEncoding.EncodeToString([]byte("a-longer-credential-id-32-bytes!")) {
		t.Fatalf("b64. credential id not decoded: %s", only.Passkeys[0].CredentialID)
	}
	checkPasskeySigns(t, only.Passkeys[0], &k2.priv.PublicKey)
	if !strings.Contains(only.Dropped[0].Reason, "EdDSA") {
		t.Fatalf("drop reason %q", only.Dropped[0].Reason)
	}

	totp := bwFind(set, "totp", "GitHub")
	if totp == nil || totp.Get("secret") != "JBSWY3DPEHPK3PXP" || totp.Get("domain") != "github.com" || len(totp.Problems) != 0 {
		t.Fatalf("github totp %+v", totp)
	}
	if st := bwFind(set, "totp", "Steam"); st == nil || len(st.Problems) == 0 || !strings.Contains(st.Problems[0], "Steam") {
		t.Fatalf("steam totp should be a problem: %+v", st)
	}
	if ot := bwFind(set, "totp", "Otp link"); ot == nil || ot.Get("secret") != "JBSWY3DPEHPK3PXP" || len(ot.Problems) != 0 {
		t.Fatalf("otpauth totp %+v", ot)
	}
	if n := bwFind(set, "note", "Door codes"); n == nil || !strings.Contains(n.Get("content"), "front 1234") || !strings.Contains(n.Get("content"), "Back: 5678") {
		t.Fatalf("note %+v", n)
	}
	card := bwFind(set, "banking", "Visa")
	if card == nil || card.Get("details") != "4111111111111111" || card.Get("cvv") != "123" || card.Get("expiry") != "03/29" || card.Get("type") != "Card" {
		t.Fatalf("card %+v", card)
	}
	if bwFind(set, "note", "Visa notes") == nil {
		t.Fatal("cardholder and brand should land in a companion note")
	}
	me := bwFind(set, "contact", "Me")
	if me == nil || me.Get("email") != "ada@example.com" || !strings.Contains(me.Get("address"), "London N1") {
		t.Fatalf("contact %+v", me)
	}
	if g := bwFind(set, "govid", "Ada Lovelace national ID"); g == nil || g.Get("id_number") != "123-45-6789" || g.Get("type") != "National ID" {
		t.Fatalf("ssn govid %+v", g)
	}
	if g := bwFind(set, "govid", "Ada Lovelace passport"); g == nil || g.Get("id_number") != "P123" {
		t.Fatalf("passport govid %+v", g)
	}
	if k := bwFind(set, "ssh_key", "Deploy key"); k == nil || !strings.HasPrefix(k.Get("private_key"), "-----BEGIN OPENSSH") {
		t.Fatalf("ssh key %+v", k)
	}
	if bwFind(set, "password", "Trashed") != nil || len(set.Warnings) == 0 {
		t.Fatalf("trashed item should be skipped with a warning: %v", set.Warnings)
	}

	v := &Vault{}
	res, plan := ApplyTransfer(v, set, PlanOptions{KeepSpaces: true}, nil)
	if res.Failed != 0 {
		t.Fatalf("apply errors: %v", res.Errors)
	}
	if res.PasskeysAdded != 2 {
		t.Fatalf("passkeys added %d", res.PasskeysAdded)
	}
	dupConflict := false
	for _, r := range plan.Rows {
		if r.Title == "GitHub" && r.Type == "password" && r.Status == RowConflict && r.Match != nil && r.Match.Row >= 0 {
			dupConflict = true
		}
	}
	if !dupConflict {
		t.Fatal("second GitHub login should conflict with the first row in the file")
	}
	ref, ok := v.FindItem(ItemID("password", "Work", "GitHub"))
	if !ok {
		t.Fatal("GitHub login not in the Work space")
	}
	if len(v.Entries[ref.Index].Passkeys) != 1 {
		t.Fatal("passkey not attached")
	}
	vers := v.Desktop.Versions[ref.ID]
	if len(vers) != 2 || vers[0].F["password"] != "old-2" || vers[1].F["password"] != "old-1" {
		t.Fatalf("history versions %+v", vers)
	}
	if !v.isFavoriteID(ref.ID) {
		t.Fatal("favorite lost")
	}
}

func TestBitwardenIndependentVector(t *testing.T) {
	if _, err := ParseTransfer("bw.json", []byte(bwVector), "", ""); TransferErrorCode(err) != TransferNeedsPassword {
		t.Fatalf("no password: %v", err)
	}
	if _, err := ParseTransfer("bw.json", []byte(bwVector), "wrong", ""); TransferErrorCode(err) != TransferWrongPassword {
		t.Fatalf("wrong password: %v", err)
	}
	set, err := ParseTransfer("bw.json", []byte(bwVector), bwVectorPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if !set.Encrypted || set.FormatLabel != "Bitwarden (password protected)" {
		t.Fatalf("label %q", set.FormatLabel)
	}
	it := bwFind(set, "password", "Example")
	if it == nil || it.Get("password") != "hunter2" || it.Folder != "Work" || len(it.Passkeys) != 1 || !strings.Contains(it.Get("notes"), "PIN: 1234") {
		t.Fatalf("vector login %+v", it)
	}
	der, _ := base64.RawURLEncoding.DecodeString(bwVectorKey)
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	checkPasskeySigns(t, it.Passkeys[0], &key.(*ecdsa.PrivateKey).PublicKey)
	if bwFind(set, "totp", "Example") == nil {
		t.Fatal("vector totp missing")
	}
}

func TestBitwardenArgon2AndAccountEncrypted(t *testing.T) {
	plain := []byte(`{"encrypted":false,"folders":[],"items":[{"type":1,"name":"A","login":{"username":"u","password":"p"}}]}`)
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	keys, err := bwDeriveKeys("pw", salt, 1, 3, 16, 2)
	if err != nil {
		t.Fatal(err)
	}
	val, _ := bwEncryptString([]byte(newUUID()), keys)
	data, _ := bwEncryptString(plain, keys)
	kt, it, mem, par := 1, 3, 16, 2
	env, _ := json.Marshal(bwExport{Encrypted: true, PasswordProtected: true, Salt: salt, KdfType: &kt, KdfIterations: &it, KdfMemory: &mem, KdfParallelism: &par, EncKeyValidation: val, Data: data})
	set, err := ParseTransfer("bw.json", env, "pw", "")
	if err != nil || bwFind(set, "password", "A") == nil {
		t.Fatalf("argon2 export: %v", err)
	}
	if _, err := ParseTransfer("bw.json", env, "nope", ""); TransferErrorCode(err) != TransferWrongPassword {
		t.Fatalf("argon2 wrong password: %v", err)
	}
	acct := []byte(`{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","folders":[],"items":[]}`)
	if _, err := ParseTransfer("bw.json", acct, "", ""); TransferErrorCode(err) != TransferAccountEncrypted {
		t.Fatalf("account encrypted: %v", err)
	}
}

func TestBitwardenCSVImport(t *testing.T) {
	csv := "folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\n" +
		"Work,1,login,GitHub,hello,\"Recovery: r@x.com\nPIN: 1\",0,,\"https://github.com,https://gist.github.com\",octo,pw,JBSWY3DPEHPK3PXP\n" +
		",,note,Wifi,the note,,0,,,,,\n"
	set, err := ParseTransfer("bitwarden.csv", []byte(csv), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Format != "bitwarden-csv" {
		t.Fatalf("format %q", set.Format)
	}
	gh := bwFind(set, "password", "GitHub")
	if gh == nil || gh.Folder != "Work" || !gh.Favorite || gh.Get("website") != "https://github.com" || !strings.Contains(gh.Get("notes"), "PIN: 1") {
		t.Fatalf("csv login %+v", gh)
	}
	if bwFind(set, "totp", "GitHub") == nil || bwFind(set, "note", "Wifi") == nil {
		t.Fatal("csv totp or note missing")
	}
}

func TestBitwardenZipAttachments(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("data.json")
	w.Write([]byte(`{"encrypted":false,"folders":[],"items":[{"id":"abc","type":2,"name":"Lease","notes":"x","secureNote":{"type":0}}]}`))
	w, _ = zw.Create("attachments/abc/lease.pdf")
	w.Write([]byte("%PDF-1.4 test"))
	zw.Close()
	set, err := ParseTransfer("bitwarden_export.zip", buf.Bytes(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	doc := bwFind(set, "document", "Lease · lease.pdf")
	if doc == nil || doc.File == nil || string(doc.File.Data) != "%PDF-1.4 test" || len(doc.Problems) != 0 {
		t.Fatalf("attachment %+v", doc)
	}
}

func TestBitwardenExportRoundTrip(t *testing.T) {
	k := newBWTestKey(t)
	jwk, err := jwkFromECDSA(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	cred := make([]byte, 16)
	rand.Read(cred)
	pk, err := NewPasskey(ImportedPasskey{RPID: "github.com", UserName: "octo", UserHandle: "dXNlci0x", CredentialID: base64.RawURLEncoding.EncodeToString(cred), Key: jwk, SignCount: 3})
	if err != nil {
		t.Fatal(err)
	}
	long := make([]byte, 40)
	rand.Read(long)
	pk2, _ := NewPasskey(ImportedPasskey{RPID: "webauthn.io", UserName: "w", CredentialID: base64.RawURLEncoding.EncodeToString(long), Key: jwk})
	items := []TransferItem{
		{Type: "password", Title: "GitHub", Space: "Work", Favorite: true, Fields: map[string]any{"account": "GitHub", "username": "octo", "password": "pw", "website": "github.com", "urls": []string{"gist.github.com"}, "notes": "n"}, Passkeys: []Passkey{pk, pk2}, Link: -1},
		{Type: "totp", Title: "GitHub", Space: "Work", Fields: map[string]any{"account": "GitHub", "secret": "JBSWY3DPEHPK3PXP", "domain": "github.com"}, Link: -1},
		{Type: "totp", Title: "Lonely", Fields: map[string]any{"account": "Lonely", "secret": "JBSWY3DPEHPK3PXQ"}, Link: -1},
		{Type: "apikey", Title: "Stripe", Fields: map[string]any{"name": "Stripe", "service": "stripe", "key": "sk_live_x"}, Link: -1},
		{Type: "banking", Title: "Visa", Fields: map[string]any{"label": "Visa", "type": "Card", "details": "4111", "cvv": "1", "expiry": "03/29"}, Link: -1},
	}
	for _, pw := range []string{"", "export-pass"} {
		out, err := writeBitwardenExport(items, ExportOptions{Password: pw})
		if err != nil {
			t.Fatal(err)
		}
		set, err := ParseTransfer("bitwarden.json", out, pw, "")
		if err != nil {
			t.Fatalf("reimport (%q): %v", pw, err)
		}
		gh := bwFind(set, "password", "GitHub")
		if gh == nil || gh.Folder != "Work" || !gh.Favorite || gh.Get("password") != "pw" || gh.Get("website") != "https://github.com" || len(gh.Passkeys) != 2 || len(gh.Dropped) != 0 {
			t.Fatalf("round trip login %+v", gh)
		}
		for i, want := range []Passkey{pk, pk2} {
			got := gh.Passkeys[i]
			if got.CredentialID != want.CredentialID || got.RPID != want.RPID || got.UserHandle != want.UserHandle || got.SignCount != want.SignCount {
				t.Fatalf("passkey %d: %+v vs %+v", i, got, want)
			}
			checkPasskeySigns(t, got, &k.priv.PublicKey)
		}
		if tt := bwFind(set, "totp", "GitHub"); tt == nil || tt.Get("secret") != "JBSWY3DPEHPK3PXP" {
			t.Fatal("attached totp lost")
		}
		if bwFind(set, "totp", "Lonely") == nil {
			t.Fatal("standalone totp lost")
		}
		if n := bwFind(set, "note", "Stripe"); n == nil || !strings.Contains(n.Get("content"), "sk_live_x") {
			t.Fatalf("api key as note %+v", n)
		}
		if c := bwFind(set, "banking", "Visa"); c == nil || c.Get("expiry") != "03/29" || c.Get("details") != "4111" {
			t.Fatalf("card %+v", c)
		}
		if pw != "" && !set.Encrypted {
			t.Fatal("expected encrypted export")
		}
	}
}
