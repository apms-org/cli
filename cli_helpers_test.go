package main

import (
	"encoding/json"
	"strings"
	"testing"

	src "github.com/aaravmaloo/apm/src"
)

func bundledVault(t *testing.T) *src.Vault {
	t.Helper()
	v := &src.Vault{}
	if _, err := v.AddItem("password", "Work", map[string]any{"account": "GitHub", "username": "me", "password": "pw-1", "website": "github.com", "urls": []string{"gist.github.com"}, "fields": []map[string]any{{"label": "PIN", "value": "1234", "hidden": true}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.AddItem("totp", "Work", map[string]any{"account": "GitHub 2FA", "secret": "JBSWY3DPEHPK3PXP", "domain": "github.com"}); err != nil {
		t.Fatal(err)
	}
	key := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"private-scalar"}`)
	v.Entries[0].Passkeys = []src.Passkey{
		{ID: "p1", RPID: "github.com", UserName: "me", CredentialID: "cred-1", PrivateKey: key, SignCount: 4},
		{ID: "p2", RPID: "github.com", UserName: "me-alt", CredentialID: "cred-2", PrivateKey: key},
	}
	return v
}

func refOf(t *testing.T, v *src.Vault, typ, title string) src.VaultItemRef {
	t.Helper()
	for _, r := range v.ItemRefs() {
		if r.Spec.ID == typ && r.Title == title {
			return r
		}
	}
	t.Fatalf("no %s called %s", typ, title)
	return src.VaultItemRef{}
}

func TestLoginCardShowsBundle(t *testing.T) {
	v := bundledVault(t)
	look := newItemLookup(v)
	lines, copies := itemCard(look, refOf(t, v, "password", "GitHub"), false)
	card := strings.Join(lines, "\n")
	for _, want := range []string{"GitHub", "Login · space: Work · 2FA on · 2 passkeys", "Username", "me", "One-time code", `from Authenticator "GitHub 2FA"`, "Other websites", "gist.github.com", "PIN", "Passkeys", "github.com · me-alt"} {
		if !strings.Contains(card, want) {
			t.Fatalf("card is missing %q:\n%s", want, card)
		}
	}
	if strings.Contains(card, "pw-1") || strings.Contains(card, "1234") {
		t.Fatalf("card shows a secret without reveal:\n%s", card)
	}
	var labels []string
	for _, c := range copies {
		labels = append(labels, c.label)
	}
	if got := strings.Join(labels, ","); got != "Password,Username,One-time code,PIN" {
		t.Fatalf("copy targets = %s", got)
	}

	totp, _ := itemCard(look, refOf(t, v, "totp", "GitHub 2FA"), false)
	if s := strings.Join(totp, "\n"); !strings.Contains(s, "Used by") || !strings.Contains(s, "GitHub") {
		t.Fatalf("authenticator card should name the login using it:\n%s", s)
	}
}

func TestDraftSaveKeepsPasskeys(t *testing.T) {
	v := bundledVault(t)
	d := newItemDraft(v, refOf(t, v, "password", "GitHub"))
	d.set("account", "GitHub Work")
	d.set("username", "me2")
	d.set("password", "pw-2")
	d.setCustom(append(d.custom, src.CustomField{Label: "Recovery email", Value: "a@b.c"}))
	if _, err := d.save(); err != nil {
		t.Fatal(err)
	}
	e := v.Entries[0]
	if e.Account != "GitHub Work" || e.Username != "me2" || e.Password != "pw-2" || e.Space != "Work" || e.Website != "github.com" || len(e.URLs) != 1 || len(e.Fields) != 2 {
		t.Fatalf("edited entry = %+v", e)
	}
	if len(e.Passkeys) != 2 || e.Passkeys[0].CredentialID != "cred-1" || e.Passkeys[0].SignCount != 4 || !strings.Contains(string(e.Passkeys[0].PrivateKey), "private-scalar") {
		t.Fatalf("passkeys lost on edit: %+v", e.Passkeys)
	}

	d = newItemDraft(v, refOf(t, v, "password", "GitHub Work"))
	list := append([]src.Passkey(nil), d.passkeys...)
	list[1].Label = "Laptop"
	d.setPasskeys(list[1:])
	d.setSpace("default")
	if _, err := d.save(); err != nil {
		t.Fatal(err)
	}
	e = v.Entries[0]
	if e.Space != "" || len(e.Passkeys) != 1 || e.Passkeys[0].CredentialID != "cred-2" || e.Passkeys[0].Label != "Laptop" {
		t.Fatalf("passkey rename/remove or move = %+v", e)
	}
}

func TestDraftRenamesAuthenticatorKeepingSite(t *testing.T) {
	v := bundledVault(t)
	d := newItemDraft(v, refOf(t, v, "totp", "GitHub 2FA"))
	d.set("account", "GitHub OTP")
	if _, err := d.save(); err != nil {
		t.Fatal(err)
	}
	if v.TOTPEntries[0].Space != "Work" || v.TOTPDomainLinks["github.com"] != "GitHub OTP" {
		t.Fatalf("totp rename should keep space and site link: %+v %v", v.TOTPEntries[0], v.TOTPDomainLinks)
	}
	if got := totpSiteSuffix(v, "GitHub OTP"); got != " (github.com)" {
		t.Fatalf("site suffix = %q", got)
	}
	if _, err := findTOTPAccount(v, "otp"); err != nil {
		t.Fatalf("partial match: %v", err)
	}
}

func TestDraftRejectsTakenName(t *testing.T) {
	v := bundledVault(t)
	if _, err := v.AddItem("password", "Work", map[string]any{"account": "GitLab", "password": "x"}); err != nil {
		t.Fatal(err)
	}
	d := newItemDraft(v, refOf(t, v, "password", "GitLab"))
	d.set("account", "GitHub")
	if _, err := d.save(); err == nil {
		t.Fatal("renaming onto an existing login should fail")
	}
	if v.Entries[1].Account != "GitLab" {
		t.Fatalf("failed save changed the vault: %+v", v.Entries[1])
	}
}

func TestSearchMatchesBundleAndGovID(t *testing.T) {
	v := bundledVault(t)
	v.CurrentSpace = "Work"
	if _, err := v.AddItem("govid", "Work", map[string]any{"name": "Passport", "id_number": "X1234567", "type": "Passport"}); err != nil {
		t.Fatal(err)
	}
	look := newItemLookup(v)
	got := searchItems(look, "gist.github")
	if len(got) != 1 || got[0].Identifier != "GitHub" {
		t.Fatalf("search by other website = %+v", got)
	}
	for _, r := range searchItems(look, "passport") {
		if r.Type == "Government ID" {
			ref, ok := look.ref(r)
			if !ok || ref.Title != "Passport" {
				t.Fatalf("government ID did not resolve to its item: %+v %v", ref, ok)
			}
			if main := resultLine(look, r); strings.Contains(main, "X1234567") {
				t.Fatalf("list shows the ID number: %q", main)
			}
			return
		}
	}
	t.Fatal("search by name did not find the government ID")
}
