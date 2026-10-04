package apm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func keepassXMLFixture(t *testing.T) (string, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	cred := []byte("credential-id-0123456789")
	xml := `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><RecycleBinUUID>cmVjeWNsZWJpbnV1aWQxMg==</RecycleBinUUID></Meta>
  <Root>
    <Group>
      <UUID>cm9vdHJvb3Ryb290cm9vdA==</UUID>
      <Name>Passwords</Name>
      <Entry>
        <UUID>ZW50cnkx</UUID>
        <Tags>dev;work</Tags>
        <String><Key>Title</Key><Value>GitHub</Value></String>
        <String><Key>UserName</Key><Value>octo</Value></String>
        <String><Key>Password</Key><Value Protected="True">current-pw</Value></String>
        <String><Key>URL</Key><Value>https://github.com</Value></String>
        <String><Key>Notes</Key><Value>main</Value></String>
        <String><Key>otp</Key><Value>otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&amp;period=30&amp;digits=6</Value></String>
        <String><Key>KP2A_URL_1</Key><Value>https://api.github.com</Value></String>
        <String><Key>Recovery email</Key><Value Protected="True">me@example.com</Value></String>
        <String><Key>KPEX_PASSKEY_CREDENTIAL_ID</Key><Value>` + base64.RawURLEncoding.EncodeToString(cred) + `</Value></String>
        <String><Key>KPEX_PASSKEY_PRIVATE_KEY_PEM</Key><Value Protected="True">` + pemKey + `</Value></String>
        <String><Key>KPEX_PASSKEY_RELYING_PARTY</Key><Value>github.com</Value></String>
        <String><Key>KPEX_PASSKEY_USERNAME</Key><Value>octo</Value></String>
        <String><Key>KPEX_PASSKEY_USER_HANDLE</Key><Value>dXNlci1oYW5kbGU</Value></String>
        <Binary><Key>scan.png</Key><Value Ref="0"/></Binary>
        <Times><CreationTime>2024-01-02T03:04:05Z</CreationTime><LastModificationTime>2024-05-01T00:00:00Z</LastModificationTime></Times>
        <History>
          <Entry>
            <String><Key>Title</Key><Value>GitHub</Value></String>
            <String><Key>Password</Key><Value>older-pw</Value></String>
            <Times><LastModificationTime>2023-01-01T00:00:00Z</LastModificationTime></Times>
          </Entry>
          <Entry>
            <String><Key>Title</Key><Value>GitHub</Value></String>
            <String><Key>Password</Key><Value>old-pw</Value></String>
            <Times><LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime></Times>
          </Entry>
        </History>
      </Entry>
      <Group>
        <Name>Work</Name>
        <Group>
          <Name>Servers</Name>
          <Entry>
            <String><Key>Title</Key><Value>db01</Value></String>
            <String><Key>UserName</Key><Value>root</Value></String>
            <String><Key>Password</Key><Value>s3rver</Value></String>
            <String><Key>TimeOtp-Secret-Base32</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
            <String><Key>TimeOtp-Length</Key><Value>8</Value></String>
          </Entry>
          <Entry>
            <String><Key>Title</Key><Value>vpn</Value></String>
            <String><Key>UserName</Key><Value>me</Value></String>
            <String><Key>otp</Key><Value>key=JBSWY3DPEHPK3PXP&amp;size=6&amp;step=30</Value></String>
          </Entry>
          <Entry>
            <String><Key>Title</Key><Value>Runbook</Value></String>
            <String><Key>Notes</Key><Value>reboot twice</Value></String>
          </Entry>
        </Group>
      </Group>
      <Group>
        <UUID>cmVjeWNsZWJpbnV1aWQxMg==</UUID>
        <Name>Trash</Name>
        <Entry><String><Key>Title</Key><Value>Deleted</Value></String><String><Key>Password</Key><Value>x</Value></String></Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>`
	return xml, priv, cred
}

func TestKeePassXML(t *testing.T) {
	xml, priv, cred := keepassXMLFixture(t)
	set, err := ParseTransfer("db.xml", []byte(xml), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Format != "keepass-xml" {
		t.Fatalf("format %q", set.Format)
	}
	gh := findTransfer(set, "password", "GitHub")
	if gh == nil {
		t.Fatal("GitHub missing")
	}
	if gh.Folder != "" || gh.Get("password") != "current-pw" || gh.Get("website") != "https://github.com" {
		t.Fatalf("%+v", gh)
	}
	if urls := toStringList(gh.Fields["urls"]); len(urls) != 1 || urls[0] != "https://api.github.com" {
		t.Fatalf("urls %v", urls)
	}
	notes := gh.Get("notes")
	if !strings.Contains(notes, "main") || !strings.Contains(notes, "Recovery email: me@example.com") || !strings.Contains(notes, "Tags: dev, work") || strings.Contains(notes, "KPEX") {
		t.Fatalf("notes %q", notes)
	}
	if len(gh.History) != 2 || gh.History[0].Fields["password"] != "old-pw" || gh.History[1].Fields["password"] != "older-pw" {
		t.Fatalf("history %+v", gh.History)
	}
	if len(gh.Passkeys) != 1 || len(gh.Dropped) != 0 {
		t.Fatalf("passkeys %+v dropped %+v", gh.Passkeys, gh.Dropped)
	}
	pk := gh.Passkeys[0]
	if pk.RPID != "github.com" || pk.UserName != "octo" || pk.CredentialID != base64.RawURLEncoding.EncodeToString(cred) || pk.UserHandle != "dXNlci1oYW5kbGU" {
		t.Fatalf("passkey %+v", pk)
	}
	key, err := passkeyECDSA(pk.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("challenge"))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig) {
		t.Fatal("imported passkey key does not match the original public key")
	}
	if tp := findTransfer(set, "totp", "GitHub"); tp == nil || tp.Get("secret") != "JBSWY3DPEHPK3PXP" || len(tp.Problems) > 0 {
		t.Fatalf("otpauth totp %+v", tp)
	}
	db := findTransfer(set, "password", "db01")
	if db == nil || db.Folder != "Work/Servers" {
		t.Fatalf("db01 %+v", db)
	}
	if tp := findTransfer(set, "totp", "db01"); tp == nil || len(tp.Problems) == 0 || !strings.Contains(tp.Problems[0], "8-digit") {
		t.Fatalf("8-digit TimeOtp not flagged %+v", tp)
	}
	if tp := findTransfer(set, "totp", "vpn"); tp == nil || tp.Get("secret") != "JBSWY3DPEHPK3PXP" || len(tp.Problems) > 0 {
		t.Fatalf("KeeOtp totp %+v", tp)
	}
	if n := findTransfer(set, "note", "Runbook"); n == nil || n.Get("content") != "reboot twice" {
		t.Fatalf("note entry %+v", n)
	}
	if findTransfer(set, "password", "Deleted") != nil {
		t.Fatal("recycle bin entry imported")
	}
	joined := strings.Join(set.Warnings, "\n")
	if !strings.Contains(joined, "recycle bin") || !strings.Contains(joined, "1 attachment") {
		t.Fatalf("warnings %q", joined)
	}
}

func TestKeePassXMLBadPasskeyDropped(t *testing.T) {
	xml := `<KeePassFile><Root><Group><Name>Root</Name><Entry>
<String><Key>Title</Key><Value>Site</Value></String>
<String><Key>KPEX_PASSKEY_CREDENTIAL_ID</Key><Value>YWJj</Value></String>
<String><Key>KPEX_PASSKEY_PRIVATE_KEY_PEM</Key><Value>not a key</Value></String>
<String><Key>KPEX_PASSKEY_RELYING_PARTY</Key><Value>site.example</Value></String>
</Entry></Group></Root></KeePassFile>`
	set, err := ParseTransfer("x.xml", []byte(xml), "", "")
	if err != nil {
		t.Fatal(err)
	}
	it := findTransfer(set, "password", "Site")
	if it == nil || len(it.Passkeys) != 0 || len(it.Dropped) != 1 || it.Dropped[0].RPID != "site.example" {
		t.Fatalf("%+v", it)
	}
}

func TestKeePassCSV(t *testing.T) {
	csv := `"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Root","GitHub","octo","pw","https://github.com","hi","otpauth://totp/x?secret=JBSWY3DPEHPK3PXP","0","",""
"Root/Work/Servers","db01","root","pw2","","","","0","",""
"Root/Recycle Bin","Gone","a","b","","","","0","",""
`
	set, err := ParseTransfer("keepassxc.csv", []byte(csv), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Format != "keepass-csv" {
		t.Fatalf("generic CSV stole KeePassXC CSV: %q", set.Format)
	}
	if gh := findTransfer(set, "password", "GitHub"); gh == nil || gh.Folder != "" || gh.Get("notes") != "hi" {
		t.Fatalf("%+v", gh)
	}
	if db := findTransfer(set, "password", "db01"); db == nil || db.Folder != "Work/Servers" {
		t.Fatalf("%+v", db)
	}
	if findTransfer(set, "totp", "GitHub") == nil {
		t.Fatal("totp missing")
	}
	if findTransfer(set, "password", "Gone") != nil {
		t.Fatal("recycle bin row imported")
	}
	kp2 := "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Mail\",\"me\",\"pw\",\"https://mail.example\",\"c\"\n"
	set, err = ParseTransfer("keepass2.csv", []byte(kp2), "", "")
	if err != nil || set.Format != "keepass-csv" {
		t.Fatalf("keepass 2 csv: %v %v", err, set)
	}
	if m := findTransfer(set, "password", "Mail"); m == nil || m.Get("username") != "me" || m.Get("website") != "https://mail.example" {
		t.Fatalf("%+v", m)
	}
}

func TestKeePassKDBXUnsupported(t *testing.T) {
	data := append([]byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5}, make([]byte, 64)...)
	_, err := ParseTransfer("vault.kdbx", data, "", "")
	if TransferErrorCode(err) != TransferUnsupported || !strings.Contains(err.Error(), "XML") {
		t.Fatalf("got %v", err)
	}
}
