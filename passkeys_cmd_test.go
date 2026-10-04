package main

import (
	"encoding/json"
	"strings"
	"testing"

	src "github.com/aaravmaloo/apm/src"
)

func TestEditLoginEntryKeepsPasskeys(t *testing.T) {
	v := &src.Vault{}
	if _, err := v.AddItem("password", "Work", map[string]any{"account": "GitHub", "username": "me", "password": "pw-1", "website": "github.com", "urls": []string{"gist.github.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.AddItem("totp", "Work", map[string]any{"account": "GitHub 2FA", "secret": "JBSWY3DPEHPK3PXP", "domain": "github.com"}); err != nil {
		t.Fatal(err)
	}
	key := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"private-scalar"}`)
	v.Entries[0].Passkeys = []src.Passkey{{ID: "p1", RPID: "github.com", CredentialID: "cred-1", PrivateKey: key, SignCount: 4}}

	if err := editLoginEntry(v, v.Entries[0], "GitHub Work", "me2", "pw-2", nil); err != nil {
		t.Fatal(err)
	}
	e := v.Entries[0]
	if e.Account != "GitHub Work" || e.Username != "me2" || e.Password != "pw-2" || e.Space != "Work" || e.Website != "github.com" || len(e.URLs) != 1 {
		t.Fatalf("edited entry = %+v", e)
	}
	if len(e.Passkeys) != 1 || e.Passkeys[0].CredentialID != "cred-1" || string(e.Passkeys[0].PrivateKey) != string(key) || e.Passkeys[0].SignCount != 4 {
		t.Fatalf("passkey lost on edit: %+v", e.Passkeys)
	}
	lines := strings.Join(loginExtraLines(v, e), "\n")
	if !strings.Contains(lines, "Passkeys: 1 (github.com)") || !strings.Contains(lines, "One-time code: GitHub 2FA") {
		t.Fatalf("login extra lines = %q", lines)
	}

	if err := editTOTPEntry(v, v.TOTPEntries[0], "GitHub OTP", "JBSWY3DPEHPK3PXP"); err != nil {
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
