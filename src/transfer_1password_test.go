package apm

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func build1PUX(t *testing.T, doc any, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("export.attributes")
	_, _ = w.Write([]byte(`{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}`))
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	w, _ = zw.Create("export.data")
	_, _ = w.Write(data)
	for name, b := range files {
		w, _ = zw.Create("files/" + name)
		_, _ = w.Write(b)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func field(id, title, kind string, value any) map[string]any {
	return map[string]any{"id": id, "title": title, "value": map[string]any{kind: value}}
}

func onePuxFixture(t *testing.T) []byte {
	login := map[string]any{
		"uuid": "a1", "favIndex": 1, "state": "active", "categoryUuid": "001",
		"overview": map[string]any{"title": "GitHub", "url": "https://github.com/login", "urls": []any{map[string]any{"label": "", "url": "https://github.com/login"}, map[string]any{"label": "api", "url": "https://api.github.com"}}, "tags": []string{"dev", "work"}},
		"details": map[string]any{
			"loginFields": []any{
				map[string]any{"value": "octo", "id": "", "name": "username", "fieldType": "T", "designation": "username"},
				map[string]any{"value": "hunter2", "id": "", "name": "password", "fieldType": "P", "designation": "password"},
			},
			"notesPlain": "Main account",
			"sections": []any{map[string]any{"title": "Security", "fields": []any{
				field("TOTP_1", "one-time password", "totp", "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
				field("q1", "Security question", "concealed", "blue"),
				field("f1", "", "file", map[string]any{"fileName": "codes.txt", "documentId": "doc2"}),
			}}},
			"passwordHistory": []any{map[string]any{"value": "old-pass", "time": 1690000000}},
		},
	}
	card := map[string]any{
		"uuid": "c1", "categoryUuid": "002", "overview": map[string]any{"title": "Visa"},
		"details": map[string]any{"sections": []any{map[string]any{"title": "", "fields": []any{
			field("cardholder", "cardholder name", "string", "Octo Cat"),
			field("ccnum", "number", "creditCardNumber", "4111111111111111"),
			field("cvv", "verification number", "concealed", "123"),
			field("expiry", "expiry date", "monthYear", 202712),
		}}}},
	}
	wifi := map[string]any{
		"uuid": "w1", "categoryUuid": "109", "overview": map[string]any{"title": "Home router"},
		"details": map[string]any{"sections": []any{map[string]any{"fields": []any{
			field("network_name", "network name", "string", "Home-5G"),
			field("wireless_password", "wireless network password", "concealed", "wifipass"),
			field("wireless_security", "wireless security", "menu", "WPA2 Personal"),
			field("password", "base station password", "concealed", "admin123"),
		}}}},
	}
	ssh := map[string]any{
		"uuid": "s1", "categoryUuid": "114", "overview": map[string]any{"title": "homelab"},
		"details": map[string]any{"sections": []any{map[string]any{"fields": []any{
			field("private_key", "private key", "sshKey", map[string]any{"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "metadata": map[string]any{"privateKey": "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----"}}),
		}}}},
	}
	doc := map[string]any{
		"uuid": "d1", "categoryUuid": "006", "overview": map[string]any{"title": "Lease"},
		"details": map[string]any{"documentAttributes": map[string]any{"fileName": "lease.pdf", "documentId": "doc1", "decryptedSize": 5}},
	}
	trashed := map[string]any{"uuid": "t1", "state": "trashed", "categoryUuid": "001", "overview": map[string]any{"title": "Old"}}
	archived := map[string]any{"uuid": "r1", "state": "archived", "categoryUuid": "003", "overview": map[string]any{"title": "Archived note"}, "details": map[string]any{"notesPlain": "keep me"}}
	crypto := map[string]any{"uuid": "x1", "categoryUuid": "115", "overview": map[string]any{"title": "Wallet"}, "details": map[string]any{"sections": []any{map[string]any{"fields": []any{field("phrase", "recovery phrase", "concealed", "apple banana")}}}}}
	export := map[string]any{"accounts": []any{map[string]any{
		"attrs": map[string]any{"accountName": "Me"},
		"vaults": []any{
			map[string]any{"attrs": map[string]any{"name": "Personal", "type": "P"}, "items": []any{login, card, trashed, archived, doc}},
			map[string]any{"attrs": map[string]any{"name": "Work", "type": "U"}, "items": []any{wifi, ssh, crypto}},
		},
	}}}
	return build1PUX(t, export, map[string][]byte{"doc1__lease.pdf": []byte("%PDF1"), "doc2__codes.txt": []byte("1234")})
}

func findTransfer(set *TransferSet, typ, title string) *TransferItem {
	for i := range set.Items {
		if set.Items[i].Type == typ && set.Items[i].Title == title {
			return &set.Items[i]
		}
	}
	return nil
}

func TestOnePassword1PUX(t *testing.T) {
	set, err := ParseTransfer("export.1pux", onePuxFixture(t), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Format != "1password-1pux" {
		t.Fatalf("format %q", set.Format)
	}
	gh := findTransfer(set, "password", "GitHub")
	if gh == nil {
		t.Fatal("GitHub login missing")
	}
	if gh.Get("username") != "octo" || gh.Get("password") != "hunter2" || gh.Get("website") != "https://github.com/login" || !gh.Favorite || gh.Folder != "Personal" {
		t.Fatalf("login fields wrong: %+v", gh)
	}
	if urls := toStringList(gh.Fields["urls"]); len(urls) != 1 || urls[0] != "https://api.github.com" {
		t.Fatalf("urls %v", urls)
	}
	notes := gh.Get("notes")
	for _, want := range []string{"Main account", "Security question: blue", "Tags: dev, work"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("notes %q missing %q", notes, want)
		}
	}
	if len(gh.History) != 1 || gh.History[0].Fields["password"] != "old-pass" {
		t.Fatalf("history %+v", gh.History)
	}
	totp := findTransfer(set, "totp", "GitHub")
	if totp == nil || totp.Get("secret") != "JBSWY3DPEHPK3PXP" || totp.Get("domain") != "github.com" || len(totp.Problems) > 0 {
		t.Fatalf("totp %+v", totp)
	}
	att := findTransfer(set, "document", "GitHub - codes.txt")
	if att == nil || att.File == nil || string(att.File.Data) != "1234" {
		t.Fatalf("attachment %+v", att)
	}
	card := findTransfer(set, "banking", "Visa")
	if card == nil || card.Get("details") != "4111111111111111" || card.Get("cvv") != "123" || card.Get("expiry") != "12/27" || card.Get("type") != "Card" {
		t.Fatalf("card %+v", card)
	}
	if n := findTransfer(set, "note", "Visa notes"); n == nil || !strings.Contains(n.Get("content"), "Octo Cat") {
		t.Fatalf("card leftovers not kept: %+v", n)
	}
	wifi := findTransfer(set, "wifi", "Home-5G")
	if wifi == nil || wifi.Get("password") != "wifipass" || wifi.Get("security_type") != "WPA2 Personal" || wifi.Folder != "Work" {
		t.Fatalf("wifi %+v", wifi)
	}
	if n := findTransfer(set, "note", "Home-5G notes"); n == nil || !strings.Contains(n.Get("content"), "admin123") {
		t.Fatalf("base station password not kept: %+v", n)
	}
	ssh := findTransfer(set, "ssh_key", "homelab")
	if ssh == nil || !strings.Contains(ssh.Get("private_key"), "BEGIN PRIVATE KEY") {
		t.Fatalf("ssh %+v", ssh)
	}
	doc := findTransfer(set, "document", "Lease")
	if doc == nil || doc.File == nil || string(doc.File.Data) != "%PDF1" || len(doc.Problems) > 0 {
		t.Fatalf("document %+v", doc)
	}
	if findTransfer(set, "password", "Old") != nil {
		t.Fatal("trashed item imported")
	}
	arch := findTransfer(set, "note", "Archived note")
	if arch == nil || len(arch.Warnings) == 0 || arch.Get("content") != "keep me" {
		t.Fatalf("archived %+v", arch)
	}
	if w := findTransfer(set, "note", "Wallet"); w == nil || !strings.Contains(w.Get("content"), "recovery phrase: apple banana") {
		t.Fatalf("crypto wallet %+v", w)
	}
	joined := strings.Join(set.Warnings, "\n")
	if !strings.Contains(joined, "trash") || !strings.Contains(joined, "passkeys out of .1pux") {
		t.Fatalf("warnings %q", joined)
	}
}

func TestOnePassword1PUXSingleVaultNoFolder(t *testing.T) {
	export := map[string]any{"accounts": []any{map[string]any{"vaults": []any{map[string]any{"attrs": map[string]any{"name": "Personal"}, "items": []any{
		map[string]any{"categoryUuid": "005", "overview": map[string]any{"title": "Router admin"}, "details": map[string]any{"password": "pw"}},
	}}}}}}
	set, err := ParseTransfer("x.1pux", build1PUX(t, export, nil), "", "")
	if err != nil {
		t.Fatal(err)
	}
	it := findTransfer(set, "password", "Router admin")
	if it == nil || it.Folder != "" || it.Get("password") != "pw" {
		t.Fatalf("%+v", it)
	}
}

func TestOnePasswordCSV(t *testing.T) {
	csv := "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n" +
		"GitHub,https://github.com,octo,pw1,otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP,true,false,dev;work,hello\n" +
		"Bank,https://bank.example,me,pw2,,false,true,,\n"
	set, err := ParseTransfer("1password.csv", []byte(csv), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Format != "1password-csv" {
		t.Fatalf("generic CSV stole 1Password CSV: %q", set.Format)
	}
	gh := findTransfer(set, "password", "GitHub")
	if gh == nil || !gh.Favorite || !strings.Contains(gh.Get("notes"), "Tags: dev, work") || gh.Get("password") != "pw1" {
		t.Fatalf("%+v", gh)
	}
	if tp := findTransfer(set, "totp", "GitHub"); tp == nil || tp.Get("secret") != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("totp %+v", tp)
	}
	if b := findTransfer(set, "password", "Bank"); b == nil || len(b.Warnings) == 0 {
		t.Fatalf("archived warning missing %+v", b)
	}
}
