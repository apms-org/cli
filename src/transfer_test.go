package apm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testPasskey(t *testing.T, rp, user string) (Passkey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	jwk, err := PasskeyKeyFromPKCS8(der)
	if err != nil {
		t.Fatal(err)
	}
	cred := make([]byte, 16)
	_, _ = rand.Read(cred)
	pk, err := NewPasskey(ImportedPasskey{RPID: rp, UserName: user, UserHandle: base64.RawURLEncoding.EncodeToString([]byte("uh-" + user)), CredentialID: base64.RawURLEncoding.EncodeToString(cred), Key: jwk})
	if err != nil {
		t.Fatal(err)
	}
	return pk, priv
}

func assertKeySigns(t *testing.T, pk Passkey, pub *ecdsa.PublicKey) {
	t.Helper()
	priv, err := passkeyECDSA(pk.PrivateKey)
	if err != nil {
		t.Fatalf("stored key unreadable: %v", err)
	}
	h := sha256.Sum256([]byte("challenge"))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		t.Fatal("imported passkey key does not match the original public key")
	}
}

func testVault() *Vault {
	v := &Vault{Spaces: []string{"default"}}
	_, _ = v.AddItem("password", "", map[string]any{"account": "GitHub", "username": "alice", "password": "old-pass", "website": "https://github.com"})
	_, _ = v.AddItem("totp", "", map[string]any{"account": "GitHub", "secret": "JBSWY3DPEHPK3PXP"})
	_, _ = v.AddItem("note", "", map[string]any{"name": "Runbook", "content": "restart it"})
	return v
}

func TestTransferPlanStatusesAndApply(t *testing.T) {
	v := testVault()
	pk, priv := testPasskey(t, "github.com", "alice")
	set := &TransferSet{Format: "test"}
	same := NewTransferItem("note", "Runbook")
	same.Set("content", "restart it")
	set.Add(same)
	gh := NewTransferItem("password", "GitHub")
	gh.Set("username", "alice")
	gh.Set("password", "old-pass")
	gh.Set("website", "https://github.com/login")
	gh.Set("notes", "recovery email is b@example.com")
	gh.Passkeys = []Passkey{pk}
	set.Add(gh)
	dup := NewTransferItem("password", "github.com (work)")
	dup.Set("username", "ALICE")
	dup.Set("password", "new-pass")
	dup.Set("website", "github.com")
	set.Add(dup)
	fresh := NewTransferItem("password", "Linear")
	fresh.Set("username", "alice")
	fresh.Set("password", "x")
	set.Add(fresh)
	again := NewTransferItem("password", "Linear")
	again.Set("username", "alice")
	again.Set("password", "x")
	set.Add(again)
	code := NewTransferItem("totp", "GH copy")
	code.Set("secret", "jbsw y3dp ehpk 3pxp")
	set.Add(code)
	bad := NewTransferItem("totp", "Steam")
	bad.Set("secret", "x")
	bad.Problem("Steam Guard codes are not supported")
	set.Add(bad)
	set.finish()

	plan := PlanTransfer(v, set, PlanOptions{})
	want := []string{RowIdentical, RowConflict, RowDuplicate, RowNew, RowIdentical, RowIdentical, RowInvalid}
	for i, r := range plan.Rows {
		if r.Status != want[i] {
			t.Errorf("row %d %q: status %s, want %s (%s)", i, r.Title, r.Status, want[i], r.Reason)
		}
	}
	if r := plan.Rows[1]; r.Default != ActionMerge || r.NewPasskeys != 1 {
		t.Errorf("additive conflict should default to merge with 1 new passkey, got %s %d", r.Default, r.NewPasskeys)
	}
	if r := plan.Rows[2]; r.Default != ActionSkip || r.Match == nil || r.Match.Title != "GitHub" {
		t.Errorf("duplicate with a different password should default to skip and point at GitHub: %+v", r)
	}
	if r := plan.Rows[4]; r.Match == nil || r.Match.Row != 3 {
		t.Errorf("second Linear should match row 3 of the file, got %+v", r.Match)
	}
	if plan.Summary.New != 1 || plan.Summary.Invalid != 1 || plan.Summary.NewPasskeys != 1 {
		t.Errorf("summary off: %+v", plan.Summary)
	}

	res, _ := ApplyTransfer(v, set, PlanOptions{}, map[int]string{2: ActionAdd})
	if res.Added != 2 || res.Merged != 1 || res.PasskeysAdded != 1 {
		t.Fatalf("apply result %+v", res)
	}
	var ghEntry Entry
	for _, e := range v.Entries {
		if e.Account == "GitHub" {
			ghEntry = e
		}
	}
	if ghEntry.Password != "old-pass" || !strings.Contains(ghEntry.Notes, "recovery email") || len(ghEntry.Passkeys) != 1 {
		t.Fatalf("merge should keep the password and add notes and the passkey: %+v", ghEntry)
	}
	assertKeySigns(t, ghEntry.Passkeys[0], &priv.PublicKey)
	found := false
	for _, e := range v.Entries {
		if e.Account == "github.com (work)" && e.Password == "new-pass" {
			found = true
		}
	}
	if !found {
		t.Fatal("keep both should add the duplicate as its own item")
	}

	again2, _ := ApplyTransfer(v, set, PlanOptions{}, nil)
	if again2.Changed() != 0 || again2.PasskeysAdded != 0 {
		t.Fatalf("importing the same file twice must change nothing, got %+v", again2)
	}
}

func TestTransferReplaceKeepsHistoryAndNeverDropsPasskeys(t *testing.T) {
	v := testVault()
	pk, _ := testPasskey(t, "github.com", "alice")
	v.Entries[0].Passkeys = []Passkey{pk}
	set := &TransferSet{}
	it := NewTransferItem("password", "GitHub")
	it.Set("password", "rotated")
	it.Set("website", "https://github.com")
	set.Add(it)
	set.finish()
	res, plan := ApplyTransfer(v, set, PlanOptions{}, map[int]string{0: ActionReplace})
	if plan.Rows[0].Status != RowConflict || res.Replaced != 1 {
		t.Fatalf("want a replaced conflict, got %s %+v", plan.Rows[0].Status, res)
	}
	if v.Entries[0].Password != "rotated" || len(v.Entries[0].Passkeys) != 1 {
		t.Fatalf("replace must update the password and keep passkeys: %+v", v.Entries[0])
	}
	ref, _ := v.findRefAt(v.itemSliceSpec("password"), 0)
	if vers := v.Desktop.Versions[ref.ID]; len(vers) != 1 || vers[0].F["password"] != "old-pass" {
		t.Fatalf("replace must keep the old value in the item history, got %+v", vers)
	}
}

func (v *Vault) itemSliceSpec(id string) ItemTypeSpec { s, _ := ItemTypeByID(id); return s }

func TestTransferSpacesAndFolders(t *testing.T) {
	v := testVault()
	set := &TransferSet{}
	a := NewTransferItem("password", "Jira")
	a.Set("password", "p")
	a.Folder = "Work"
	set.Add(a)
	b := NewTransferItem("password", "Bank")
	b.Set("password", "p")
	set.Add(b)
	set.finish()
	plan := PlanTransfer(v, set, PlanOptions{Space: "Imported", KeepSpaces: true})
	if plan.Rows[0].Space != "Work" || plan.Rows[1].Space != "Imported" {
		t.Fatalf("folders should become spaces: %q %q", plan.Rows[0].Space, plan.Rows[1].Space)
	}
	if strings.Join(plan.Summary.Spaces, ",") != "Imported,Work" {
		t.Fatalf("new spaces %v", plan.Summary.Spaces)
	}
	res, _ := ApplyTransfer(v, set, PlanOptions{Space: "Imported", KeepSpaces: true}, nil)
	if len(res.SpacesCreated) != 2 || !v.hasSpace("Work") {
		t.Fatalf("spaces not created: %+v %v", res, v.Spaces)
	}
}

func TestAPMExportRoundTripWithPasskeysFilesAndEncryption(t *testing.T) {
	v := testVault()
	pk, priv := testPasskey(t, "github.com", "alice")
	v.Entries[0].Passkeys = []Passkey{pk}
	v.Entries[0].Notes = "a note"
	_, _ = v.AddItem("photo", "Work", map[string]any{"name": "Scan", "file": map[string]any{"name": "scan.png", "data": base64.StdEncoding.EncodeToString([]byte("PNGDATA"))}})
	v.Spaces = append(v.Spaces, "Work")
	refs := v.ItemRefs()
	v.addFavorite(refs[0].ID)
	for _, pw := range []string{"", "export-pass-123"} {
		data, sum, err := v.ExportTransfer("apm", ExportSelection{Passkeys: true, Files: true}, ExportOptions{Password: pw, Secrets: true})
		if err != nil {
			t.Fatal(err)
		}
		if sum.Items != 4 || sum.Passkeys != 1 || sum.Files != 1 {
			t.Fatalf("summary %+v", sum)
		}
		if pw != "" && strings.Contains(string(data), "old-pass") {
			t.Fatal("encrypted export leaks plaintext")
		}
		if pw != "" {
			if _, err := ParseTransfer("x.json", data, "", ""); TransferErrorCode(err) != TransferNeedsPassword {
				t.Fatalf("want needs_password, got %v", err)
			}
			if _, err := ParseTransfer("x.json", data, "nope", ""); TransferErrorCode(err) != TransferWrongPassword {
				t.Fatalf("want wrong_password, got %v", err)
			}
		}
		set, err := ParseTransfer("x.json", data, pw, "")
		if err != nil {
			t.Fatal(err)
		}
		if set.Format != "apm" || set.Encrypted != (pw != "") {
			t.Fatalf("format %s encrypted %v", set.Format, set.Encrypted)
		}
		fresh := &Vault{}
		res, _ := ApplyTransfer(fresh, set, PlanOptions{KeepSpaces: true}, nil)
		if res.Added != 4 || res.PasskeysAdded != 1 {
			t.Fatalf("round trip result %+v", res)
		}
		if fresh.Entries[0].Notes != "a note" || fresh.Entries[0].Password != "old-pass" {
			t.Fatalf("login did not round trip: %+v", fresh.Entries[0])
		}
		assertKeySigns(t, fresh.Entries[0].Passkeys[0], &priv.PublicKey)
		if len(fresh.PhotoFiles) != 1 || string(fresh.PhotoFiles[0].Content) != "PNGDATA" || fresh.PhotoFiles[0].Space != "Work" {
			t.Fatalf("photo did not round trip: %+v", fresh.PhotoFiles)
		}
		if fresh.Desktop == nil || len(fresh.Desktop.Favorites) != 1 {
			t.Fatal("favorite did not round trip")
		}
		plan := PlanTransfer(v, set, PlanOptions{KeepSpaces: true})
		if plan.Summary.Identical != 4 {
			t.Fatalf("re-importing an export of the same vault should be all identical: %+v", plan.Summary)
		}
	}
}

func TestAPMLegacyFormats(t *testing.T) {
	v1 := `{"entries":[{"account":"Mail","username":"me","password":"pw"}],"totp_entries":[{"account":"Mail","secret":"JBSWY3DPEHPK3PXP"}],"secure_notes":[{"name":"N","content":"c"}],"api_keys":[],"ssh_keys":[],"wifi_credentials":[],"recovery_codes":[{"service":"GH","codes":["a","b"]}],"tokens":[]}`
	set, err := ParseTransfer("export.json", []byte(v1), "", "")
	if err != nil || set.FormatLabel != "APM export (version 1)" || len(set.Items) != 4 {
		t.Fatalf("v1: %v %+v", err, set)
	}
	enc, _ := EncryptData([]byte(v1), "pw12345678")
	set, err = ParseTransfer("export.json", enc, "pw12345678", "")
	if err != nil || !set.Encrypted || len(set.Items) != 4 {
		t.Fatalf("v1 encrypted: %v", err)
	}
	gui := `{"apm_export":1,"items":[{"type":"password","space":"","fields":{"account":"X","password":"y"}}]}`
	if set, err = ParseTransfer("apm-export.json", []byte(gui), "", ""); err != nil || set.Items[0].Title != "X" {
		t.Fatalf("gui v1: %v", err)
	}
	vault := testVault()
	blob, err := EncryptVault(vault, "master-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTransfer("vault.dat", blob, "", ""); TransferErrorCode(err) != TransferNeedsPassword {
		t.Fatalf("vault.dat without password: %v", err)
	}
	set, err = ParseTransfer("vault.dat", blob, "master-pass-1", "")
	// The GitHub code folds into the GitHub login when the vault is opened.
	if err != nil || set.Format != "apm-vault" || len(set.Items) != 2 {
		t.Fatalf("vault.dat: %v", err)
	}
	if set.Items[0].Type != "password" || set.Items[0].Get("totp") != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("vault.dat login should carry its 2FA key: %+v", set.Items[0])
	}
}

func TestGenericCSVAndText(t *testing.T) {
	chrome := "name,url,username,password,note\nGitHub,https://github.com/,alice,pw1,hello\n,https://linear.app/login,bob,pw2,\n"
	set, err := ParseTransfer("Chrome Passwords.csv", []byte(chrome), "", "")
	if err != nil || set.Format != "chrome-csv" || len(set.Items) != 2 {
		t.Fatalf("chrome: %v %+v", err, set)
	}
	if set.Items[1].Title != "linear.app" || set.Items[0].Get("notes") != "hello" {
		t.Fatalf("chrome mapping: %+v", set.Items)
	}
	firefox := "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://a.com\",\"u\",\"p\",,\"\",\"{x}\",\"1\",\"1\",\"1\"\n"
	if set, err = ParseTransfer("logins.csv", []byte(firefox), "", ""); err != nil || set.Format != "firefox-csv" {
		t.Fatalf("firefox: %v", err)
	}
	safari := "Title,URL,Username,Password,Notes,OTPAuth\nGH,https://github.com,al,pw,,otpauth://totp/GitHub:al?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n"
	set, err = ParseTransfer("Passwords.csv", []byte(safari), "", "")
	if err != nil || set.Format != "safari-csv" || len(set.Items) != 2 || set.Items[1].Type != "totp" || set.Items[1].Get("domain") != "github.com" {
		t.Fatalf("safari: %v %+v", err, set)
	}
	txt := "otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP&issuer=Acme\notpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP&digits=8\n"
	set, err = ParseTransfer("codes.txt", []byte(txt), "", "")
	if err != nil || len(set.Items) != 2 || set.Items[0].Title != "Acme (bob)" || len(set.Items[1].Problems) == 0 {
		t.Fatalf("txt: %v %+v", err, set)
	}
	if _, err := ParseTransfer("x.kdbx", []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 2}, "", ""); TransferErrorCode(err) != TransferUnsupported || !strings.Contains(err.Error(), "XML") {
		t.Fatalf("kdbx should explain how to export XML: %v", err)
	}
}

func TestExportExclusionsAndCSV(t *testing.T) {
	v := testVault()
	pk, _ := testPasskey(t, "github.com", "alice")
	v.Entries[0].Passkeys = []Passkey{pk}
	_, _, sum, err := v.PlanExport("csv", ExportSelection{Passkeys: true}, ExportOptions{Secrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Items != 3 || len(sum.Excluded) != 1 || !strings.Contains(sum.Excluded[0].Reason, "passkeys") {
		t.Fatalf("csv should say it cannot hold the passkey: %+v", sum)
	}
	data, _, err := v.ExportTransfer("csv", ExportSelection{}, ExportOptions{Secrets: true})
	if err != nil || !strings.Contains(string(data), "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP") {
		t.Fatalf("csv export: %v\n%s", err, data)
	}
	set, err := ParseTransfer("apm.csv", data, "", "")
	if err != nil {
		t.Fatal(err)
	}
	plan := PlanTransfer(v, set, PlanOptions{})
	if plan.Summary.Identical != 3 {
		t.Fatalf("csv round trip should be identical: %+v", plan.Summary)
	}
	quiet, _, _ := v.ExportTransfer("txt", ExportSelection{}, ExportOptions{Secrets: false})
	if strings.Contains(string(quiet), "old-pass") || strings.Contains(string(quiet), "JBSWY3DP") {
		t.Fatal("text export without secrets leaks a secret")
	}
}

func TestCredentialIDsAndTOTP(t *testing.T) {
	if got := NormalizePasskeyCredentialID("00112233-4455-6677-8899-aabbccddeeff"); got != base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Fatalf("guid: %s", got)
	}
	if BitwardenCredentialID(NormalizePasskeyCredentialID("00112233-4455-6677-8899-aabbccddeeff")) != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatal("16-byte IDs should go back to a GUID")
	}
	if NormalizePasskeyCredentialID("b64.AQID") != "AQID" || NormalizePasskeyCredentialID("AQI+/w==") != "AQI-_w" {
		t.Fatal("b64 forms")
	}
	for raw, bad := range map[string]bool{"JBSW Y3DP EHPK 3PXP": false, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP": false, "steam://ABC": true, "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP": true, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256": true, "not base32!": true} {
		if _, p := TOTPSecretFrom(raw); (p != "") != bad {
			t.Errorf("%s: problem %q", raw, p)
		}
	}
	raw, _ := json.Marshal(map[string]string{"kty": "EC"})
	if _, err := NewPasskey(ImportedPasskey{RPID: "a.com", CredentialID: "AQID", Key: raw}); err == nil {
		t.Fatal("a key without a private part must be rejected")
	}
}

func TestTransferDefaultsNeverLosePasskeysOrAccounts(t *testing.T) {
	v := &Vault{}
	pk, _ := testPasskey(t, "example.com", "me")
	set := &TransferSet{}
	a := NewTransferItem("password", "Example")
	a.Set("username", "me")
	a.Set("password", "one")
	a.Set("website", "https://example.com")
	set.Add(a)
	b := NewTransferItem("password", "example.com")
	b.Set("username", "me")
	b.Set("password", "two")
	b.Set("website", "https://example.com")
	b.Passkeys = []Passkey{pk}
	set.Add(b)
	c := NewTransferItem("password", "Example")
	c.Set("username", "someone-else")
	c.Set("password", "three")
	set.Add(c)
	set.finish()
	plan := PlanTransfer(v, set, PlanOptions{})
	if plan.Rows[1].Status != RowDuplicate || plan.Rows[1].Default != ActionMerge {
		t.Fatalf("a duplicate that brings a passkey must default to merge: %+v", plan.Rows[1])
	}
	if plan.Rows[2].Status != RowConflict || plan.Rows[2].Default != ActionAdd {
		t.Fatalf("same name with another username must default to keep both: %+v", plan.Rows[2])
	}
	res, _ := ApplyTransfer(v, set, PlanOptions{}, nil)
	if res.PasskeysAdded != 1 || res.Added != 2 || res.Merged != 1 || len(v.Entries) != 2 {
		t.Fatalf("defaults must keep every passkey and account: %+v", res)
	}
	if v.Entries[0].Password != "one" || len(v.Entries[0].Passkeys) != 1 {
		t.Fatalf("merge must keep the first password and attach the passkey: %+v", v.Entries[0])
	}
	if again, _ := ApplyTransfer(v, set, PlanOptions{}, nil); again.Changed() != 0 {
		t.Fatalf("re-import after keep both must change nothing: %+v", again)
	}
}
