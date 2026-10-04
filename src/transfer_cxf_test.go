package apm

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func cxfTestPasskey(t *testing.T, rp string, count int64) (Passkey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jwkFromECDSA(priv)
	if err != nil {
		t.Fatal(err)
	}
	cred := make([]byte, 32)
	_, _ = rand.Read(cred)
	return Passkey{ID: newUUID(), RPID: rp, UserName: "alice", UserDisplayName: "Alice", UserHandle: base64.RawURLEncoding.EncodeToString([]byte("user-1")),
		CredentialID: base64.RawURLEncoding.EncodeToString(cred), PrivateKey: jwk, SignCount: count, CreatedAt: "2025-03-01T10:00:00.000Z"}, priv
}

func cxfFind(set *TransferSet, typ, title string) *TransferItem {
	for i := range set.Items {
		if set.Items[i].Type == typ && set.Items[i].Title == title {
			return &set.Items[i]
		}
	}
	return nil
}

func assertSigns(t *testing.T, pk Passkey, pub *ecdsa.PublicKey) {
	t.Helper()
	priv, err := passkeyECDSA(pk.PrivateKey)
	if err != nil {
		t.Fatalf("imported key unreadable: %v", err)
	}
	digest := sha256.Sum256([]byte("challenge"))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("imported passkey does not sign for the original public key")
	}
}

func TestCXFRoundTrip(t *testing.T) {
	v := &Vault{}
	must := func(_ VaultItemRef, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(v.AddItem("password", "", map[string]any{"account": "GitHub", "username": "alice", "password": "pw-1", "website": "github.com", "urls": []string{"gist.github.com"}, "notes": "recovery email is old"}))
	fresh, freshPriv := cxfTestPasskey(t, "github.com", 0)
	used, _ := cxfTestPasskey(t, "github.com", 7)
	v.Entries[0].Passkeys = []Passkey{fresh, used}
	must(v.AddItem("totp", "", map[string]any{"account": "GitHub", "secret": "JBSWY3DPEHPK3PXP"}))
	must(v.AddItem("totp", "", map[string]any{"account": "Lone code", "secret": "KRSXG5CTMVRXEZLU", "domain": "lone.example"}))
	must(v.AddItem("note", "Work", map[string]any{"name": "Runbook", "content": "line one\nline two"}))
	must(v.AddItem("banking", "", map[string]any{"label": "Travel card", "type": "Card", "details": "4111111111111111", "cvv": "123", "expiry": "08/29"}))
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(edPriv, "homelab")
	if err != nil {
		t.Fatal(err)
	}
	must(v.AddItem("ssh_key", "", map[string]any{"name": "homelab", "private_key": string(pem.EncodeToMemory(block))}))
	must(v.AddItem("wifi", "", map[string]any{"ssid": "Home-5G", "password": "wifi-pass", "security_type": "WPA2 Personal", "router_ip": "192.168.1.1"}))
	must(v.AddItem("apikey", "", map[string]any{"name": "Stripe", "service": "stripe.com", "key": "sk_test_123"}))
	must(v.AddItem("govid", "", map[string]any{"name": "My passport", "type": "Passport", "id_number": "X1234567", "expiry": "2030-01-01"}))
	must(v.AddItem("license", "", map[string]any{"product_name": "Sketch", "serial_key": "AAAA-BBBB"}))

	data, sum, err := v.ExportTransfer("cxf", ExportSelection{Passkeys: true}, ExportOptions{VaultName: "Personal", Secrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Format != "cxf" {
		t.Fatalf("format %q", sum.Format)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["exporterRpId"] != cxfExporterRpID {
		t.Fatalf("exporterRpId %v", doc["exporterRpId"])
	}
	if strings.Contains(string(data), used.CredentialID) {
		t.Fatal("a passkey with a non-zero sign count was exported")
	}

	set, err := ParseTransfer("apm.json", data, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Format != "cxf" {
		t.Fatalf("detected %q", set.Format)
	}
	login := cxfFind(set, "password", "GitHub")
	if login == nil {
		t.Fatal("login missing")
	}
	if login.Get("username") != "alice" || login.Get("password") != "pw-1" || login.Get("notes") != "recovery email is old" {
		t.Fatalf("login fields %v", login.Fields)
	}
	if h := normalizeDomain(login.Get("website")); h != "github.com" {
		t.Fatalf("website %q", login.Get("website"))
	}
	if urls := toStringList(login.Fields["urls"]); len(urls) != 1 || normalizeDomain(urls[0]) != "gist.github.com" {
		t.Fatalf("urls %v", login.Fields["urls"])
	}
	if len(login.Passkeys) != 1 || login.Passkeys[0].CredentialID != fresh.CredentialID || login.Passkeys[0].UserHandle != fresh.UserHandle || login.Passkeys[0].SignCount != 0 {
		t.Fatalf("passkeys %+v", login.Passkeys)
	}
	assertSigns(t, login.Passkeys[0], &freshPriv.PublicKey)
	code := cxfFind(set, "totp", "GitHub")
	if code == nil || code.Get("secret") != "JBSWY3DPEHPK3PXP" || len(code.Problems) > 0 {
		t.Fatalf("linked totp %+v", code)
	}
	if lone := cxfFind(set, "totp", "Lone code"); lone == nil || lone.Get("secret") != "KRSXG5CTMVRXEZLU" || lone.Get("domain") != "lone.example" {
		t.Fatalf("lone totp %+v", lone)
	}
	note := cxfFind(set, "note", "Runbook")
	if note == nil || note.Get("content") != "line one\nline two" || note.Space != "Work" || !note.HasSpace || note.Folder != "Work" {
		t.Fatalf("note %+v", note)
	}
	card := cxfFind(set, "banking", "Travel card")
	if card == nil || card.Get("details") != "4111111111111111" || card.Get("cvv") != "123" || card.Get("expiry") != "08/29" {
		t.Fatalf("card %+v", card)
	}
	key := cxfFind(set, "ssh_key", "homelab")
	if key == nil {
		t.Fatal("ssh key missing")
	}
	parsed, err := ssh.ParseRawPrivateKey([]byte(key.Get("private_key")))
	if err != nil {
		t.Fatalf("ssh key unreadable: %v", err)
	}
	if p, ok := parsed.(*ed25519.PrivateKey); !ok || !p.Equal(edPriv) {
		t.Fatalf("ssh key changed: %T", parsed)
	}
	if w := cxfFind(set, "wifi", "Home-5G"); w == nil || w.Get("password") != "wifi-pass" || w.Get("security_type") != "WPA2 Personal" || w.Get("router_ip") != "192.168.1.1" {
		t.Fatalf("wifi %+v", w)
	}
	if k := cxfFind(set, "apikey", "Stripe"); k == nil || k.Get("key") != "sk_test_123" || k.Get("service") != "stripe.com" {
		t.Fatalf("apikey %+v", k)
	}
	if g := cxfFind(set, "govid", "My passport"); g == nil || g.Get("id_number") != "X1234567" || g.Get("type") != "Passport" {
		t.Fatalf("govid %+v", g)
	}
	if l := cxfFind(set, "license", "Sketch"); l == nil || l.Get("serial_key") != "AAAA-BBBB" {
		t.Fatalf("license %+v", l)
	}

	// Importing into an empty vault brings every passkey in usable.
	dst := &Vault{}
	res, _ := ApplyTransfer(dst, set, PlanOptions{KeepSpaces: true}, nil)
	if res.Failed != 0 || res.PasskeysAdded != 1 {
		t.Fatalf("apply %+v", res)
	}
}

func cxfPKCS8(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func TestCXFSpecShapes(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	account := `{
  "id": "YWNjb3VudA",
  "username": "johndoe",
  "email": "john@example.com",
  "collections": [{"id": "Y29sbA", "title": "Personal", "items": [{"item": "aXRlbTE"}]}],
  "items": [
    {"id": "aXRlbTE", "creationAt": -5, "title": "WebAuthn.io", "favorite": true,
     "scope": {"urls": ["https://webauthn.io"], "androidApps": []},
     "credentials": [
       {"type": "passkey", "credentialId": "Y3JlZGVudGlhbElkRXhhbXBsZQ", "rpId": "webauthn.io", "username": "johndoe", "userDisplayName": "John Doe",
        "userHandle": "dXNlci1oYW5kbGU", "key": "` + cxfPKCS8(t, p256) + `", "fido2Extensions": {"credBlob": "AAEC"}},
       {"type": "basic-auth", "username": {"fieldType": "string", "value": "johndoe"}, "password": "plain-string-password"},
       {"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "period": 30, "digits": 8, "algorithm": "sha1", "issuer": "WebAuthn.io"},
       {"type": "future-credential", "whatever": 1},
       {"type": "custom-fields", "fields": [{"fieldType": "string", "label": "Security question", "value": "blue"}]}
     ],
     "tags": ["dev"]},
    {"id": "aXRlbTI", "title": "Ed site",
     "credentials": [{"type": "passkey", "credentialId": "ZWQ", "rpId": "ed.example", "username": "ed", "userDisplayName": "Ed", "userHandle": "ZWQ", "key": "` + cxfPKCS8(t, ed) + `"}]},
    {"id": "aXRlbTM", "title": "Shopping list", "credentials": [{"type": "note", "content": {"fieldType": "string", "value": "milk"}}]},
    {"id": "aXRlbTQ", "title": "Mystery", "credentials": [{"type": "future-credential"}]}
  ]
}`
	header := `{"version": {"major": 1, "minor": 0}, "exporterRpId": "exporter.example.com", "exporterDisplayName": "Exporter", "timestamp": 0, "accounts": [` + account + `]}`
	for _, doc := range []string{account, header} {
		if detectCXF("x.json", []byte(doc)) < 90 {
			t.Fatal("not detected as CXF")
		}
		set, err := ParseTransfer("x.json", []byte(doc), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if set.Format != "cxf" {
			t.Fatalf("format %q", set.Format)
		}
		login := cxfFind(set, "password", "WebAuthn.io")
		if login == nil || login.Get("password") != "plain-string-password" || login.Get("username") != "johndoe" || !login.Favorite || login.Folder != "Personal" {
			t.Fatalf("login %+v", login)
		}
		if len(login.Passkeys) != 1 || login.Passkeys[0].RPID != "webauthn.io" || login.Passkeys[0].SignCount != 0 {
			t.Fatalf("passkeys %+v", login.Passkeys)
		}
		assertSigns(t, login.Passkeys[0], &p256.PublicKey)
		if !strings.Contains(login.Get("notes"), "Security question: blue") || !strings.Contains(login.Get("notes"), "Tags: dev") {
			t.Fatalf("notes %q", login.Get("notes"))
		}
		if len(login.Warnings) == 0 || !strings.Contains(login.Warnings[0], "extension") {
			t.Fatalf("warnings %v", login.Warnings)
		}
		code := cxfFind(set, "totp", "WebAuthn.io")
		if code == nil || len(code.Problems) == 0 || !strings.Contains(code.Problems[0], "8-digit") {
			t.Fatalf("8-digit totp not flagged: %+v", code)
		}
		ed := cxfFind(set, "password", "Ed site")
		if ed == nil || len(ed.Passkeys) != 0 || len(ed.Dropped) != 1 || !strings.Contains(ed.Dropped[0].Reason, "ES256") {
			t.Fatalf("ed25519 passkey %+v", ed)
		}
		if ed.Get("website") != "https://ed.example" {
			t.Fatalf("passkey-only website %q", ed.Get("website"))
		}
		if n := cxfFind(set, "note", "Shopping list"); n == nil || n.Get("content") != "milk" {
			t.Fatalf("note %+v", n)
		}
		if m := cxfFind(set, "note", "Mystery"); m == nil || len(m.Problems) == 0 {
			t.Fatalf("unknown-only item %+v", m)
		}
		warned := false
		for _, w := range set.Warnings {
			if strings.Contains(w, "future-credential") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("no warning for unknown type: %v", set.Warnings)
		}
	}
}

func TestCXFDetectIgnoresOtherJSON(t *testing.T) {
	for _, doc := range []string{`{"encrypted":false,"items":[{"type":1,"name":"x","login":{}}]}`, `{"format":"apm-export","version":2,"items":[]}`, `[]`} {
		if s := detectCXF("x.json", []byte(doc)); s != 0 {
			t.Fatalf("%s detected as CXF (%d)", doc, s)
		}
	}
}
