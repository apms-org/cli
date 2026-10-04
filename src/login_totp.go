package apm

import (
	"fmt"
	"strings"
)

// NormalizeLoginTOTP cleans a 2FA setup key typed or pasted into a login. It
// accepts a bare base32 key or an otpauth:// link and returns the bare key.
func NormalizeLoginTOTP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	secret, problem := TOTPSecretFrom(raw)
	if problem != "" {
		return "", fmt.Errorf("%w: %s", ErrItemInvalid, problem)
	}
	return secret, nil
}

// LoginTOTPs returns the 2FA codes stored inside logins, shaped like
// Authenticator entries so code lists can show both side by side.
func (v *Vault) LoginTOTPs() []TOTPEntry {
	var out []TOTPEntry
	for _, e := range v.Entries {
		if strings.TrimSpace(e.TOTP) != "" {
			out = append(out, TOTPEntry{Account: e.Account, Secret: e.TOTP, Space: e.Space})
		}
	}
	return out
}

// AllTOTPs is every 2FA code in the vault: Authenticator items first, then
// codes stored inside logins.
func (v *Vault) AllTOTPs() []TOTPEntry {
	out := append([]TOTPEntry{}, v.TOTPEntries...)
	return append(out, v.LoginTOTPs()...)
}

// HoldsTOTP reports whether an item produces 2FA codes: an Authenticator item,
// or a login with its own key.
func (v *Vault) HoldsTOTP(ref VaultItemRef) bool {
	switch ref.Spec.ID {
	case "totp":
		return true
	case "password":
		return ref.Index < len(v.Entries) && strings.TrimSpace(v.Entries[ref.Index].TOTP) != ""
	}
	return false
}

// MergeLinkedTOTP moves Authenticator items into the login they belong to.
// A code moves only when exactly one login in the same space matches it, by
// name or by a linked domain, and that login has no code yet. Anything
// ambiguous stays a standalone Authenticator item. It returns how many moved.
func (v *Vault) MergeLinkedTOTP() int {
	if len(v.TOTPEntries) == 0 || len(v.Entries) == 0 {
		return 0
	}
	claimed := map[int]bool{}
	kept := v.TOTPEntries[:0:0]
	moved := 0
	for _, t := range v.TOTPEntries {
		secret := strings.TrimSpace(t.Secret)
		if secret == "" {
			kept = append(kept, t)
			continue
		}
		domains := map[string]bool{}
		for d, acc := range v.TOTPDomainLinks {
			if acc == t.Account {
				if h := normalizeDomain(d); h != "" {
					domains[h] = true
				}
			}
		}
		match := -1
		count := 0
		for i, e := range v.Entries {
			if !strings.EqualFold(e.Space, t.Space) {
				continue
			}
			byName := strings.EqualFold(strings.TrimSpace(e.Account), strings.TrimSpace(t.Account))
			byDomain := false
			if h := normalizeDomain(e.Website); h != "" && domains[h] {
				byDomain = true
			}
			if byName || byDomain {
				match = i
				count++
			}
		}
		if count != 1 || claimed[match] || strings.TrimSpace(v.Entries[match].TOTP) != "" {
			kept = append(kept, t)
			continue
		}
		claimed[match] = true
		v.Entries[match].TOTP = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
		moved++
	}
	if moved == 0 {
		return 0
	}
	v.TOTPEntries = kept
	remaining := map[string]bool{}
	for _, t := range kept {
		remaining[t.Account] = true
	}
	for d, acc := range v.TOTPDomainLinks {
		if !remaining[acc] {
			delete(v.TOTPDomainLinks, d)
		}
	}
	return moved
}

// splitLoginExtras reshapes logins for formats that only know plain logins:
// a login's 2FA key becomes its own linked code, which every exporter already
// pairs back with the login, and custom fields are written into the notes.
func splitLoginExtras(items []TransferItem) []TransferItem {
	out := make([]TransferItem, 0, len(items))
	for _, it := range items {
		if it.Type != "password" {
			out = append(out, it)
			continue
		}
		f := make(map[string]any, len(it.Fields))
		for k, val := range it.Fields {
			f[k] = val
		}
		it.Fields = f
		secret := strings.TrimSpace(toStringValue(f["totp"]))
		delete(f, "totp")
		if extra := toCustomFields(f["fields"]); len(extra) > 0 {
			lines := make([]string, 0, len(extra))
			for _, cf := range extra {
				lines = append(lines, strings.TrimSpace(cf.Label+": "+cf.Value))
			}
			f["notes"] = joinNotes(toStringValue(f["notes"]), strings.Join(lines, "\n"))
		}
		delete(f, "fields")
		out = append(out, it)
		if secret == "" {
			continue
		}
		t := NewTransferItem("totp", it.Title)
		t.Space, t.HasSpace, t.Link = it.Space, it.HasSpace, len(out)-1
		t.Set("secret", secret)
		if host := normalizeDomain(it.Get("website")); host != "" {
			t.Set("domain", host)
		}
		out = append(out, t)
	}
	return out
}
