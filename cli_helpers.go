package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func cliFail(format string, args ...any) {
	color.Red(format, args...)
	os.Exit(1)
}

func saveCLIVault(v *src.Vault, masterPassword string) error {
	data, err := src.EncryptVault(v, masterPassword)
	if err != nil {
		return err
	}
	return src.SaveVault(vaultPath, data)
}

func unlockForWrite(what string) (string, *src.Vault) {
	pass, v, readonly, err := src_unlockVault()
	if err != nil {
		cliFail("%v", err)
	}
	if readonly {
		cliFail("Vault is in READ-ONLY mode. Cannot %s.", what)
	}
	return pass, v
}

func findTOTPAccount(v *src.Vault, query string) (string, error) {
	query = strings.TrimSpace(query)
	exact := []string{}
	partial := map[string]bool{}
	for _, t := range v.TOTPEntries {
		if strings.EqualFold(t.Account, query) {
			if t.Account == query {
				return t.Account, nil
			}
			exact = append(exact, t.Account)
		} else if query != "" && strings.Contains(strings.ToLower(t.Account), strings.ToLower(query)) {
			partial[t.Account] = true
		}
	}
	if len(exact) > 0 {
		return exact[0], nil
	}
	if len(partial) == 1 {
		for acc := range partial {
			return acc, nil
		}
	}
	if len(partial) > 1 {
		names := []string{}
		for acc := range partial {
			names = append(names, acc)
		}
		sort.Strings(names)
		return "", fmt.Errorf("Several TOTP entries match %q: %s. Use the full name.", query, strings.Join(names, ", "))
	}
	return "", fmt.Errorf("No TOTP entry matches %q. Run 'pm totp' to see them.", query)
}

func newTOTPLinkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "link <entry> <domain>",
		Short: "Link a TOTP entry to a site so the browser extension offers its code there",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			domain := bridgeHost(args[1])
			if domain == "" || strings.ContainsAny(domain, " \t/") || (!strings.Contains(domain, ".") && domain != "localhost") {
				cliFail("Give a site like github.com.")
			}
			pass, v := unlockForWrite("link TOTP entries")
			account, err := findTOTPAccount(v, args[0])
			if err != nil {
				cliFail("%v", err)
			}
			if v.TOTPDomainLinks == nil {
				v.TOTPDomainLinks = map[string]string{}
			}
			prev := v.TOTPDomainLinks[domain]
			v.TOTPDomainLinks[domain] = account
			if err := saveCLIVault(v, pass); err != nil {
				cliFail("Error saving vault: %v", err)
			}
			src.LogAction("TOTP_LINKED", fmt.Sprintf("account=%s domain=%s", account, domain))
			color.Green("Linked %s to %s. The browser extension offers this code on %s.", account, domain, domain)
			if prev != "" && prev != account {
				fmt.Printf("%s was linked to %s before.\n", domain, prev)
			}
		},
	}
}

func newTOTPUnlinkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlink <entry> [domain]",
		Short: "Remove the site links of a TOTP entry",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			pass, v := unlockForWrite("unlink TOTP entries")
			account, err := findTOTPAccount(v, args[0])
			if err != nil {
				cliFail("%v", err)
			}
			only := ""
			if len(args) == 2 {
				only = bridgeHost(args[1])
			}
			removed := []string{}
			for _, d := range totpDomainsFor(v, account) {
				if only != "" && d != only {
					continue
				}
				delete(v.TOTPDomainLinks, d)
				removed = append(removed, d)
			}
			if len(removed) == 0 {
				fmt.Printf("%s has no linked site to remove.\n", account)
				return
			}
			if err := saveCLIVault(v, pass); err != nil {
				cliFail("Error saving vault: %v", err)
			}
			src.LogAction("TOTP_UNLINKED", fmt.Sprintf("account=%s domains=%s", account, strings.Join(removed, ",")))
			color.Green("Unlinked %s from %s.", account, strings.Join(removed, ", "))
		},
	}
}

func totpSiteSuffix(v *src.Vault, account string) string {
	if v == nil {
		return ""
	}
	if sites := totpDomainsFor(v, account); len(sites) > 0 {
		return " (" + strings.Join(sites, ", ") + ")"
	}
	for _, e := range v.Entries {
		if e.Account == account && e.TOTP != "" {
			if host := bridgeHost(e.Website); host != "" {
				return " (" + host + ")"
			}
		}
	}
	return ""
}

func loginExtraLines(v *src.Vault, e src.Entry) []string {
	out := []string{}
	if n := strings.TrimSpace(e.Notes); n != "" {
		out = append(out, "Notes: "+strings.ReplaceAll(n, "\n", "\n       "))
	}
	if n := len(e.Passkeys); n > 0 {
		rps := []string{}
		seen := map[string]bool{}
		for _, pk := range e.Passkeys {
			if rp := strings.ToLower(pk.RPID); rp != "" && !seen[rp] {
				seen[rp] = true
				rps = append(rps, pk.RPID)
			}
		}
		line := fmt.Sprintf("Passkeys: %d", n)
		if len(rps) > 0 {
			line += " (" + strings.Join(rps, ", ") + ")"
		}
		out = append(out, line)
	}
	if v == nil || e.TOTP != "" {
		return out
	}
	ix := newBridgeIndex(v)
	for _, r := range ix.refs {
		if r.Spec.ID != "password" || r.Title != e.Account || r.Space != e.Space {
			continue
		}
		if t, ok := ix.linkedTOTP(r); ok {
			line := "One-time code: " + t.Title
			if t.Space != r.Space {
				line += " (space " + spaceOrDefaultName(t.Space) + ")"
			}
			out = append(out, line)
		}
		break
	}
	return out
}

func spaceOrDefaultName(s string) string {
	if strings.TrimSpace(s) == "" {
		return "default"
	}
	return s
}

func findLoginRef(v *src.Vault, e src.Entry) (src.VaultItemRef, bool) {
	for _, r := range v.ItemRefs() {
		if r.Spec.ID == "password" && r.Title == e.Account && r.Space == e.Space {
			return r, true
		}
	}
	return src.VaultItemRef{}, false
}

func editLoginEntry(v *src.Vault, e src.Entry, account, username, password string, extra map[string]any) error {
	if password != e.Password && v.ActivePolicy.PasswordPolicy.MinLength > 0 {
		if err := v.ActivePolicy.PasswordPolicy.Validate(password); err != nil {
			return err
		}
	}
	ref, ok := findLoginRef(v, e)
	if !ok {
		return errors.New("that login no longer exists")
	}
	f := map[string]any{"account": account, "username": username, "password": password}
	for k, val := range extra {
		f[k] = val
	}
	_, _, err := v.UpdateItem(ref.ID, f, nil)
	if errors.Is(err, src.ErrItemExists) {
		return fmt.Errorf("a login called %s already exists in this space", account)
	}
	return err
}

func editTOTPEntry(v *src.Vault, e src.TOTPEntry, account, secret string) error {
	for _, r := range v.ItemRefs() {
		if r.Spec.ID == "totp" && r.Title == e.Account && r.Space == e.Space {
			_, _, err := v.UpdateItem(r.ID, map[string]any{"account": account, "secret": secret}, nil)
			if errors.Is(err, src.ErrItemExists) {
				return fmt.Errorf("a TOTP entry called %s already exists in this space", account)
			}
			return err
		}
	}
	return errors.New("that TOTP entry no longer exists")
}
