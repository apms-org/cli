package apm

import (
	"errors"
	"strings"
	"testing"
)

const testTOTP = "JBSWY3DPEHPK3PXP"

func TestMergeLinkedTOTPByNameAndDomain(t *testing.T) {
	v := &Vault{
		Entries: []Entry{
			{Account: "GitHub", Username: "me", Password: "pw"},
			{Account: "X", Website: "https://www.x.com/login", Password: "pw"},
			{Account: "Work", Password: "pw", Space: "work"},
		},
		TOTPEntries: []TOTPEntry{
			{Account: "github", Secret: "jbsw y3dp ehpk 3pxp"},
			{Account: "Twitter", Secret: testTOTP},
			{Account: "Work", Secret: testTOTP},
			{Account: "Orphan", Secret: testTOTP},
		},
		TOTPDomainLinks: map[string]string{"x.com": "Twitter", "orphan.dev": "Orphan"},
	}
	if n := v.MergeLinkedTOTP(); n != 2 {
		t.Fatalf("expected 2 codes merged, got %d", n)
	}
	if v.Entries[0].TOTP != testTOTP {
		t.Fatalf("GitHub login should hold the normalized key, got %q", v.Entries[0].TOTP)
	}
	if v.Entries[1].TOTP != testTOTP {
		t.Fatal("X login should get the code linked to x.com")
	}
	if v.Entries[2].TOTP != "" {
		t.Fatal("a code in the default space must not move into a login in another space")
	}
	got := []string{}
	for _, e := range v.TOTPEntries {
		got = append(got, e.Account)
	}
	if strings.Join(got, ",") != "Work,Orphan" {
		t.Fatalf("unexpected remaining authenticator items: %v", got)
	}
	if _, ok := v.TOTPDomainLinks["x.com"]; ok {
		t.Fatal("domain link for a merged code should be dropped")
	}
	if v.TOTPDomainLinks["orphan.dev"] != "Orphan" {
		t.Fatal("domain link for a kept code should stay")
	}
	if n := v.MergeLinkedTOTP(); n != 0 {
		t.Fatalf("merge should be idempotent, moved %d on second run", n)
	}
}

func TestMergeLinkedTOTPLeavesAmbiguousAlone(t *testing.T) {
	v := &Vault{
		Entries: []Entry{
			{Account: "Google", Website: "google.com"},
			{Account: "Gmail", Website: "google.com"},
			{Account: "Has", TOTP: "AAAAAAAAAAAAAAAA"},
		},
		TOTPEntries: []TOTPEntry{
			{Account: "Google", Secret: testTOTP},
			{Account: "Has", Secret: testTOTP},
		},
		TOTPDomainLinks: map[string]string{"google.com": "Google"},
	}
	if n := v.MergeLinkedTOTP(); n != 0 {
		t.Fatalf("expected nothing merged, got %d", n)
	}
	if len(v.TOTPEntries) != 2 || v.Entries[2].TOTP != "AAAAAAAAAAAAAAAA" {
		t.Fatal("ambiguous or occupied matches must not change anything")
	}
}

func TestDecryptVaultMergesAndFlagsRepair(t *testing.T) {
	v := &Vault{Profile: "standard", Spaces: []string{"default"}}
	if err := v.AddEntry("github", "alice", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := v.AddTOTPEntry("github", testTOTP); err != nil {
		t.Fatal(err)
	}
	data, err := EncryptVault(v, "ValidPass123!")
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecryptVault(data, "ValidPass123!", 1)
	if err != nil {
		t.Fatal(err)
	}
	if out.Entries[0].TOTP != testTOTP || len(out.TOTPEntries) != 0 {
		t.Fatal("decrypt should fold the linked code into the login")
	}
	if !out.NeedsRepair {
		t.Fatal("a merged vault should be marked for re-save")
	}
}

func TestLoginItemFieldsRoundTrip(t *testing.T) {
	v := &Vault{}
	ref, err := v.AddItem("password", "", map[string]any{
		"account":  "Bank",
		"password": "pw",
		"totp":     "otpauth://totp/Bank:me?secret=jbswy3dpehpk3pxp&issuer=Bank",
		"fields": []any{
			map[string]any{"label": "PIN", "value": "1234", "hidden": true},
			map[string]any{"label": "Branch", "value": "Main St"},
			map[string]any{"label": "", "value": ""},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := v.Entries[0]
	if e.TOTP != testTOTP {
		t.Fatalf("otpauth link should be reduced to its key, got %q", e.TOTP)
	}
	if len(e.Fields) != 2 || !e.Fields[0].Hidden || e.Fields[1].Label != "Branch" {
		t.Fatalf("unexpected custom fields: %+v", e.Fields)
	}
	f := v.ItemRecordFields(ref)
	list, ok := f["fields"].([]map[string]any)
	if !ok || len(list) != 2 || list[0]["value"] != "1234" {
		t.Fatalf("custom fields should be exposed to the app, got %#v", f["fields"])
	}
	if f["totp"] != testTOTP {
		t.Fatal("2FA key should be exposed to the app")
	}
	if _, _, err := v.UpdateItem(ref.ID, map[string]any{"totp": "not base32!"}, nil); !errors.Is(err, ErrItemInvalid) {
		t.Fatalf("an invalid key should be rejected, got %v", err)
	}
	if _, _, err := v.UpdateItem(ref.ID, map[string]any{"totp": "", "fields": []any{}}, nil); err != nil {
		t.Fatal(err)
	}
	if v.Entries[0].TOTP != "" || len(v.Entries[0].Fields) != 0 {
		t.Fatal("clearing the key and fields should empty them")
	}
}

func TestSplitLoginExtrasForExport(t *testing.T) {
	login := NewTransferItem("password", "Bank")
	login.Fields = map[string]any{"password": "pw", "website": "https://bank.com/x", "notes": "hello", "totp": testTOTP,
		"fields": []map[string]any{{"label": "PIN", "value": "1234", "hidden": true}}}
	out := splitLoginExtras([]TransferItem{login})
	if len(out) != 2 || out[1].Type != "totp" || out[1].Get("secret") != testTOTP || out[1].Get("domain") != "bank.com" {
		t.Fatalf("expected a linked code after the login, got %+v", out)
	}
	if _, ok := out[0].Fields["totp"]; ok {
		t.Fatal("the login copy should no longer carry the key")
	}
	if out[0].Get("notes") != "hello\n\nPIN: 1234" {
		t.Fatalf("custom fields should land in notes, got %q", out[0].Get("notes"))
	}
	if _, ok := login.Fields["fields"]; !ok {
		t.Fatal("splitting must not modify the vault's own field map")
	}
}
