package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type passkeyRow struct {
	entry int
	index int
	pk    src.Passkey
	name  string
	space string
}

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

func passkeyRows(v *src.Vault) []passkeyRow {
	out := []passkeyRow{}
	for i, e := range v.Entries {
		for j, pk := range e.Passkeys {
			if pk.CredentialID == "" {
				continue
			}
			out = append(out, passkeyRow{entry: i, index: j, pk: pk, name: entryDisplayName(e, i), space: e.Space})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !strings.EqualFold(out[i].pk.RPID, out[j].pk.RPID) {
			return strings.ToLower(out[i].pk.RPID) < strings.ToLower(out[j].pk.RPID)
		}
		return strings.ToLower(out[i].name) < strings.ToLower(out[j].name)
	})
	return out
}

func (r passkeyRow) matches(q string) bool {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return true
	}
	for _, f := range []string{r.pk.RPID, r.pk.UserName, r.pk.UserDisplayName, r.pk.Label, r.name, r.space, r.pk.CredentialID} {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func (r passkeyRow) user() string {
	return firstNonEmpty(r.pk.UserName, r.pk.UserDisplayName, "-")
}

func cliDate(s *string, empty string) string {
	n := parseJSTime(s)
	if n == 0 {
		return empty
	}
	return time.UnixMilli(n).Local().Format("2006-01-02")
}

func shortCredential(id string) string {
	if r := []rune(id); len(r) > 12 {
		return string(r[:12]) + "…"
	}
	return id
}

func printPasskeyTable(rows []passkeyRow) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RP\tUSER\tLABEL\tENTRY\tSPACE\tCREATED\tLAST USED\tSIGNS\tCREDENTIAL")
	for _, r := range rows {
		created := r.pk.CreatedAt
		space := r.space
		if space == "" {
			space = "default"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", r.pk.RPID, r.user(), firstNonEmpty(r.pk.Label, "-"), r.name, space, cliDate(&created, "-"), cliDate(r.pk.LastUsedAt, "never"), r.pk.SignCount, shortCredential(r.pk.CredentialID))
	}
	_ = w.Flush()
}

func passkeysByCredential(rows []passkeyRow, arg string) []passkeyRow {
	norm := normalizeCredentialID(arg)
	if norm == "" {
		return nil
	}
	for _, r := range rows {
		if normalizeCredentialID(r.pk.CredentialID) == norm {
			return []passkeyRow{r}
		}
	}
	out := []passkeyRow{}
	if len(norm) >= 6 {
		for _, r := range rows {
			if strings.HasPrefix(normalizeCredentialID(r.pk.CredentialID), norm) {
				out = append(out, r)
			}
		}
	}
	return out
}

func resolvePasskeyArg(rows []passkeyRow, arg string) (passkeyRow, error) {
	arg = strings.TrimSpace(arg)
	matches := []passkeyRow{}
	for _, r := range rows {
		if normalizeCredentialID(r.pk.CredentialID) == normalizeCredentialID(arg) {
			return r, nil
		}
	}
	for _, r := range rows {
		if strings.EqualFold(r.pk.RPID, arg) {
			matches = append(matches, r)
		}
	}
	if len(matches) == 0 {
		matches = passkeysByCredential(rows, arg)
	}
	switch len(matches) {
	case 0:
		return passkeyRow{}, fmt.Errorf("No passkey matches %q. Run 'pm passkeys list' to see them.", arg)
	case 1:
		return matches[0], nil
	}
	fmt.Printf("%d passkeys match %s:\n", len(matches), arg)
	printPasskeyTable(matches)
	fmt.Print("Credential id: ")
	pick := passkeysByCredential(matches, readInput())
	if len(pick) != 1 {
		return passkeyRow{}, errors.New("That does not identify one of the passkeys above. Nothing changed.")
	}
	return pick[0], nil
}

func newPasskeysCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "passkeys",
		Short: "List, rename and remove website passkeys saved by the browser extension",
	}
	list := &cobra.Command{
		Use:   "list [query]",
		Short: "List saved website passkeys (never shows private keys)",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			_, v, _, err := src_unlockVault()
			if err != nil {
				cliFail("%v", err)
			}
			query := ""
			if len(args) == 1 {
				query = args[0]
			}
			rows := []passkeyRow{}
			for _, r := range passkeyRows(v) {
				if r.matches(query) {
					rows = append(rows, r)
				}
			}
			if len(rows) == 0 {
				if query != "" {
					fmt.Printf("No passkeys match %q.\n", query)
				} else {
					fmt.Println("No passkeys saved yet. The browser extension saves them when you create one on a site.")
				}
				return
			}
			printPasskeyTable(rows)
			fmt.Printf("\n%d passkey(s). Use the RP or the start of the credential id with 'pm passkeys rename' or 'pm passkeys rm'.\n", len(rows))
		},
	}
	rename := &cobra.Command{
		Use:   "rename <credentialId|rpId> <label>",
		Short: "Give a saved passkey a label",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			label := strings.TrimSpace(args[1])
			if r := []rune(label); len(r) > 120 {
				label = string(r[:120])
			}
			if label == "" {
				cliFail("Give the passkey a label.")
			}
			pass, v := unlockForWrite("rename passkeys")
			row, err := resolvePasskeyArg(passkeyRows(v), args[0])
			if err != nil {
				cliFail("%v", err)
			}
			e := &v.Entries[row.entry]
			e.Passkeys[row.index].Label = label
			if err := saveCLIVault(v, pass); err != nil {
				cliFail("Error saving vault: %v", err)
			}
			src.LogAction("PASSKEY_RENAMED", fmt.Sprintf("credential=%s entry=%s", row.pk.CredentialID, e.Account))
			src.SendAlert(v, src.LevelAll, "PASSKEY RENAMED", fmt.Sprintf("Renamed a passkey for %s on %s.", row.pk.RPID, e.Account))
			color.Green("Renamed the %s passkey on %s to %q.", row.pk.RPID, row.name, label)
		},
	}
	rm := &cobra.Command{
		Use:     "rm <credentialId|rpId>",
		Aliases: []string{"remove"},
		Short:   "Remove a saved passkey",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			yes, _ := cmd.Flags().GetBool("yes")
			pass, v := unlockForWrite("remove passkeys")
			row, err := resolvePasskeyArg(passkeyRows(v), args[0])
			if err != nil {
				cliFail("%v", err)
			}
			if !yes {
				fmt.Printf("Remove the passkey for %s on %s from %s? You will not be able to sign in to %s with it again. [y/N] ", row.user(), row.pk.RPID, row.name, row.pk.RPID)
				answer := strings.ToLower(strings.TrimSpace(readInput()))
				if answer != "y" && answer != "yes" {
					fmt.Println("Nothing removed.")
					return
				}
			}
			e := &v.Entries[row.entry]
			e.Passkeys = append(e.Passkeys[:row.index], e.Passkeys[row.index+1:]...)
			if err := saveCLIVault(v, pass); err != nil {
				cliFail("Error saving vault: %v", err)
			}
			src.LogAction("PASSKEY_DELETED", fmt.Sprintf("credential=%s entry=%s", row.pk.CredentialID, e.Account))
			src.SendAlert(v, src.LevelAll, "PASSKEY DELETED", fmt.Sprintf("Removed a passkey for %s from %s.", row.pk.RPID, e.Account))
			color.Green("Removed the %s passkey from %s.", row.pk.RPID, row.name)
		},
	}
	rm.Flags().BoolP("yes", "y", false, "Remove without asking")
	root.AddCommand(list, rename, rm)
	return root
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
