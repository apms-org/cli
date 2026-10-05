package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/aaravmaloo/apm/internal/tty"
	src "github.com/aaravmaloo/apm/src"
)

func stdinIsTerminal() bool { return tty.Interactive() }

var (
	cDim  = color.New(color.Faint).SprintFunc()
	cBold = color.New(color.Bold).SprintFunc()
	cOK   = color.New(color.FgGreen).SprintFunc()
	cWarn = color.New(color.FgYellow).SprintFunc()
	cBad  = color.New(color.FgRed).SprintFunc()
	cAcc  = color.New(color.FgCyan).SprintFunc()
)

// promptHidden asks for a password with the label on stderr, so it stays
// out of piped output. Esc ends the command with cancelled.
func promptHidden(label, cancelled string) string {
	fmt.Fprint(os.Stderr, label)
	pw, err := tty.ReadLine(tty.LineOptions{Hidden: true})
	if !tty.Interactive() || !stdoutIsTerminal() {
		fmt.Fprintln(os.Stderr)
	}
	if err = exitOnInputError(err); err != nil {
		if errors.Is(err, tty.ErrCanceled) {
			exitCancelled(cancelled)
		}
		return ""
	}
	return pw
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func pad(s string, n int) string {
	w := utf8.RuneCountInString(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

func maskValue(v string, show bool) string {
	if show || v == "" {
		return v
	}
	return "••••••••"
}

func spaceLabel(s string) string {
	if strings.TrimSpace(s) == "" {
		return "default"
	}
	return s
}

// readTransfer parses a file, asking for its password on a terminal when the
// format needs one.
func readTransfer(path, password, from string, interactive bool) (*src.TransferSet, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, err)
	}
	name := filepath.Base(path)
	for attempt := 0; ; attempt++ {
		set, err := src.ParseTransfer(name, data, password, from)
		code := src.TransferErrorCode(err)
		if (code == src.TransferNeedsPassword || code == src.TransferWrongPassword) && interactive && attempt < 3 {
			if code == src.TransferWrongPassword {
				fmt.Fprintln(os.Stderr, cBad(err.Error()))
			} else {
				fmt.Fprintln(os.Stderr, err.Error())
			}
			password = promptHidden("Export password: ", "Cancelled.")
			if password == "" {
				return nil, err
			}
			continue
		}
		return set, err
	}
}

func printFormats() {
	fmt.Println(cBold("Import from"))
	for _, f := range src.TransferFormats() {
		fmt.Printf("  %s %s\n", pad(f.Label, 34), cDim(strings.Join(f.Ext, " ")))
		fmt.Printf("  %s\n", cDim(f.Help))
	}
	fmt.Println()
	fmt.Println(cBold("Export to") + cDim("  (pm export --format <id>)"))
	for _, e := range src.TransferExporters() {
		caps := []string{}
		if e.Passkeys {
			caps = append(caps, "passkeys")
		}
		if e.Encryption {
			caps = append(caps, "encryption")
		}
		if e.Files {
			caps = append(caps, "files")
		}
		fmt.Printf("  %s %s %s\n", pad(e.ID, 10), pad(e.Label, 24), cDim(strings.Join(caps, ", ")))
		fmt.Printf("  %s\n", cDim(e.Help))
	}
}

func statusMark(status string) string {
	switch status {
	case src.RowNew:
		return cOK("+")
	case src.RowIdentical:
		return cDim("=")
	case src.RowConflict:
		return cWarn("~")
	case src.RowDuplicate:
		return cWarn("?")
	case src.RowInvalid:
		return cBad("x")
	}
	return " "
}

func actionLabel(row src.TransferRow, action string) string {
	switch action {
	case src.ActionAdd:
		if row.Match != nil {
			return "keep both"
		}
		return "add"
	case src.ActionMerge:
		return "merge"
	case src.ActionReplace:
		return "replace"
	}
	return "skip"
}

func printPlanSummary(name string, set *src.TransferSet, plan *src.TransferPlan) {
	s := plan.Summary
	head := fmt.Sprintf("%s · %s · %s", cBold(name), set.FormatLabel, plural(s.Total, "item"))
	if s.Passkeys > 0 {
		head += " · " + plural(s.Passkeys, "passkey")
	}
	fmt.Println(head)
	fmt.Println()
	types := make([]string, 0, len(s.ByType))
	for t := range s.ByType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return s.ByType[types[i]] > s.ByType[types[j]] })
	for _, t := range types {
		extra := ""
		if t == "password" && s.Passkeys > 0 {
			extra = cDim(fmt.Sprintf("  %s", plural(s.Passkeys, "passkey")))
		}
		fmt.Printf("  %s %4d%s\n", pad(src.TypeLabel(t), 18), s.ByType[t], extra)
	}
	fmt.Println()
	line := func(mark string, n int, what, hint string) {
		if n == 0 {
			return
		}
		fmt.Printf("  %s %s %s\n", mark, pad(fmt.Sprintf("%d %s", n, what), 30), cDim(hint))
	}
	line(cOK("+"), s.New, "new", "")
	line(cDim("="), s.Identical, "already in your vault", "skipped")
	line(cWarn("~"), s.Conflicts, pluralWord(s.Conflicts, "conflict"), "same name, different contents")
	line(cWarn("?"), s.Duplicates, pluralWord(s.Duplicates, "possible duplicate"), "same login, key or passkey under another name")
	line(cBad("x"), s.Invalid, "can't be imported", "")
	if s.DroppedPasskeys > 0 {
		line(cBad("x"), s.DroppedPasskeys, pluralWord(s.DroppedPasskeys, "passkey")+" can't come along", "")
	}
	if len(s.Spaces) > 0 {
		fmt.Printf("  %s %s\n", cAcc("◆"), "New spaces: "+strings.Join(s.Spaces, ", "))
	}
	for _, w := range set.Warnings {
		fmt.Println()
		fmt.Println("  " + cWarn("!") + " " + w)
	}
	fmt.Println()
}

func pluralWord(n int, w string) string {
	if n == 1 {
		return w
	}
	return w + "s"
}

func plural(n int, w string) string { return fmt.Sprintf("%d %s", n, pluralWord(n, w)) }

func rowWhere(r src.TransferRow) string {
	if r.Space == "" {
		return ""
	}
	return cDim(" [" + r.Space + "]")
}

func printRows(plan *src.TransferPlan, decisions map[int]string, statuses []string, title string, showSecrets, diffs bool) {
	rows := []src.TransferRow{}
	for _, r := range plan.Rows {
		if containsStatus(statuses, r.Status) {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return
	}
	fmt.Println(cBold(title))
	for _, r := range rows {
		act := r.Default
		if d, ok := decisions[r.Index]; ok {
			act = d
		}
		extra := ""
		if n := len(r.Passkeys); n > 0 {
			extra = " " + cAcc(fmt.Sprintf("[%s]", plural(n, "passkey")))
		}
		detail := r.Subtitle
		if r.Status != src.RowNew && r.Reason != "" {
			detail = r.Reason
		}
		fmt.Printf("  %s %s %s%s%s  %s\n", statusMark(r.Status), pad(clip(r.Title, 28), 28), pad(src.TypeLabel(r.Type), 14), extra, rowWhere(r), cDim(clip(detail, 70)))
		if r.Status != src.RowInvalid && r.Status != src.RowNew {
			fmt.Printf("      %s %s\n", cDim("→"), actionLabel(r, act))
		}
		if diffs {
			for _, c := range r.Changes {
				cur, inc := maskValue(c.Current, showSecrets || !c.Secret), maskValue(c.Incoming, showSecrets || !c.Secret)
				if c.Kind == "added" {
					fmt.Printf("      %s %s %s\n", cOK("+"), pad(c.Label, 16), clip(inc, 60))
				} else {
					fmt.Printf("      %s %s %s %s %s\n", cWarn("~"), pad(c.Label, 16), clip(cur, 28), cDim("→"), clip(inc, 28))
				}
			}
		}
		for _, d := range r.Dropped {
			fmt.Printf("      %s passkey for %s %s\n", cBad("x"), d.RPID, cDim(d.Reason))
		}
	}
	fmt.Println()
}

func containsStatus(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func parsePolicy(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto", "suggested":
		return "", nil
	case "skip":
		return src.ActionSkip, nil
	case "merge":
		return src.ActionMerge, nil
	case "replace", "overwrite":
		return src.ActionReplace, nil
	case "keep-both", "keepboth", "both", "add":
		return src.ActionAdd, nil
	case "ask":
		return "ask", nil
	}
	return "", fmt.Errorf("%q is not a policy. Use skip, merge, replace, keep-both or ask", v)
}

// decideRow asks what to do with one conflicting row. ok is false when the
// user pressed Esc, which cancels the import.
func decideRow(r src.TransferRow, showSecrets bool) (action string, ok bool) {
	fmt.Printf("%s %s %s%s\n", statusMark(r.Status), cBold(r.Title), src.TypeLabel(r.Type), rowWhere(r))
	fmt.Println("  " + cDim(r.Reason))
	for _, c := range r.Changes {
		cur, inc := maskValue(c.Current, showSecrets || !c.Secret), maskValue(c.Incoming, showSecrets || !c.Secret)
		if c.Kind == "added" {
			fmt.Printf("  %s %s %s\n", cOK("+"), pad(c.Label, 16), clip(inc, 60))
		} else {
			fmt.Printf("  %s %s %s %s %s\n", cWarn("~"), pad(c.Label, 16), pad(clip(cur, 26), 26), cDim("→"), clip(inc, 26))
		}
	}
	labels := map[string]string{
		src.ActionSkip:    "Skip. Keep what you have",
		src.ActionMerge:   "Merge. Fill empty fields, add websites, notes and passkeys, keep your values",
		src.ActionReplace: "Replace. Take the file's values (your old values stay in the item's history)",
		src.ActionAdd:     "Keep both. Import it as a separate item",
	}
	opts := []string{}
	back := map[string]string{}
	for _, a := range r.Actions {
		l := labels[a]
		if a == r.Default {
			l += " (suggested)"
		}
		opts = append(opts, l)
		back[l] = a
	}
	def := 0
	for i, o := range opts {
		if back[o] == r.Default {
			def = i
		}
	}
	i, err := selectOption(tty.SelectOptions{Title: "What should APM do?", Options: opts, Initial: def})
	if err != nil {
		return "", false
	}
	fmt.Println()
	return back[opts[i]], true
}

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import from APM, 1Password, Bitwarden, KeePass, Credential Exchange or CSV, passkeys included",
		Long: `Import items from another password manager or an APM export.

APM detects the format, shows what is new, what is already in your vault and
what conflicts, and imports only what you choose. Passkeys come along from
Bitwarden, KeePassXC, Credential Exchange and APM exports.

  pm import bitwarden_export.json            review, then import
  pm import export.1pux --dry-run            only show the comparison
  pm import vault.json --on-conflict merge -y
  pm import --formats                        what APM reads and writes`,
		Args: func(cmd *cobra.Command, args []string) error {
			if f, _ := cmd.Flags().GetBool("formats"); f {
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if f, _ := cmd.Flags().GetBool("formats"); f {
				printFormats()
				return
			}
			runImport(cmd, args[0])
		},
	}
	f := cmd.Flags()
	f.StringP("password", "p", "", "Password of an encrypted export (asked for when needed)")
	f.StringP("encrypt-pass", "e", "", "Same as --password")
	_ = f.MarkHidden("encrypt-pass")
	f.String("from", "auto", "Source: auto, 1password, bitwarden, keepass, cxf, apm or csv")
	f.String("space", "", "Import into this space (default: the current space)")
	f.Bool("keep-spaces", false, "Use the file's spaces, folders or vaults as APM spaces")
	f.Bool("dry-run", false, "Show the comparison and stop")
	f.String("on-conflict", "", "Same name, different contents: skip, merge, replace, keep-both or ask")
	f.String("on-duplicate", "", "Same login or key under another name: skip, merge, replace, keep-both or ask")
	f.BoolP("yes", "y", false, "Do not ask. Use the suggested actions and the policies above")
	f.Bool("show-secrets", false, "Show secret values in the comparison")
	f.Bool("json", false, "Print the plan, or the result, as JSON")
	f.Bool("formats", false, "List the formats APM imports and exports")
	return cmd
}

func runImport(cmd *cobra.Command, path string) {
	f := cmd.Flags()
	password, _ := f.GetString("password")
	if password == "" {
		password, _ = f.GetString("encrypt-pass")
	}
	from, _ := f.GetString("from")
	space, _ := f.GetString("space")
	keep, _ := f.GetBool("keep-spaces")
	dry, _ := f.GetBool("dry-run")
	yes, _ := f.GetBool("yes")
	show, _ := f.GetBool("show-secrets")
	asJSON, _ := f.GetBool("json")
	onConflict, err := parsePolicy(mustString(f.GetString("on-conflict")))
	if err != nil {
		cliFail("%v", err)
	}
	onDuplicate, err := parsePolicy(mustString(f.GetString("on-duplicate")))
	if err != nil {
		cliFail("%v", err)
	}
	interactive := stdinIsTerminal() && !asJSON

	masterPassword, vault, readonly, err := src_unlockVault()
	if err != nil {
		cliFail("%v", err)
	}
	if readonly && !dry {
		cliFail("Vault is in READ-ONLY mode. Cannot import. Use --dry-run to only compare.")
	}
	set, err := readTransfer(path, password, from, interactive)
	if err != nil {
		cliFail("%v", err)
	}
	if !f.Changed("keep-spaces") && set.Vendor == "apm" {
		keep = true
	}
	if space == "" {
		space = vault.CurrentSpace
	}
	opt := src.PlanOptions{Space: space, KeepSpaces: keep}
	plan := src.PlanTransfer(vault, set, opt)
	name := filepath.Base(path)

	decisions := map[int]string{}
	applyPolicy := func(status, policy string) {
		if policy == "" || policy == "ask" {
			return
		}
		for _, r := range plan.Rows {
			if r.Status == status && (policy == src.ActionAdd || containsAction(r.Actions, policy)) {
				decisions[r.Index] = policy
			}
		}
	}
	applyPolicy(src.RowConflict, onConflict)
	applyPolicy(src.RowDuplicate, onDuplicate)

	if asJSON && dry {
		out, _ := json.MarshalIndent(map[string]any{"file": name, "format": set.Format, "formatLabel": set.FormatLabel, "encrypted": set.Encrypted, "warnings": set.Warnings, "plan": plan}, "", "  ")
		fmt.Println(string(out))
		return
	}
	if !asJSON {
		printPlanSummary(name, set, plan)
		all := dry
		printRows(plan, decisions, []string{src.RowConflict, src.RowDuplicate}, "Conflicts and possible duplicates", show, true)
		printRows(plan, decisions, []string{src.RowInvalid}, "Can't be imported", show, false)
		if all {
			printRows(plan, decisions, []string{src.RowNew}, "New", show, false)
			printRows(plan, decisions, []string{src.RowIdentical}, "Already in your vault", show, false)
		}
		dropped := 0
		for _, r := range plan.Rows {
			if r.Status != src.RowInvalid {
				dropped += len(r.Dropped)
			}
		}
		if dropped > 0 {
			fmt.Println(cBold("Passkeys that can't come along"))
			for _, r := range plan.Rows {
				if r.Status == src.RowInvalid {
					continue
				}
				for _, d := range r.Dropped {
					fmt.Printf("  %s %s %s  %s\n", cBad("x"), pad(clip(r.Title, 24), 24), pad(d.RPID, 24), cDim(d.Reason))
				}
			}
			fmt.Println()
		}
	}
	if dry {
		fmt.Println(cDim("Dry run. Nothing was imported. Run without --dry-run to import."))
		return
	}

	contested := []src.TransferRow{}
	for _, r := range plan.Rows {
		if (r.Status == src.RowConflict || r.Status == src.RowDuplicate) && decisions[r.Index] == "" {
			contested = append(contested, r)
		}
	}
	oneByOne := onConflict == "ask" || onDuplicate == "ask"
	if len(contested) > 0 && interactive && !yes && !oneByOne {
		choices := []string{
			"Use the suggested action for each (merge when nothing is lost, otherwise skip)",
			"Decide one by one",
			"Skip all of them",
			"Merge all (fill gaps, add passkeys, keep your values)",
			"Replace all with the file's values",
			"Keep both for all",
		}
		i, err := selectOption(tty.SelectOptions{Title: fmt.Sprintf("How should APM handle the %s?", plural(len(contested), "conflict or duplicate")), Options: choices})
		if err != nil {
			fmt.Println("Import cancelled.")
			return
		}
		ans := choices[i]
		fmt.Println()
		pick := map[string]string{choices[2]: src.ActionSkip, choices[3]: src.ActionMerge, choices[4]: src.ActionReplace, choices[5]: src.ActionAdd}
		switch ans {
		case choices[1]:
			oneByOne = true
		case choices[0]:
		default:
			for _, r := range contested {
				if a := pick[ans]; a == src.ActionAdd || containsAction(r.Actions, a) {
					decisions[r.Index] = a
				}
			}
		}
	}
	if oneByOne && interactive {
		for _, r := range contested {
			if (r.Status == src.RowConflict && onConflict != "" && onConflict != "ask") || (r.Status == src.RowDuplicate && onDuplicate != "" && onDuplicate != "ask") {
				continue
			}
			action, ok := decideRow(r, show)
			if !ok {
				fmt.Println("Import cancelled. Nothing changed.")
				return
			}
			decisions[r.Index] = action
		}
	}

	take, keys := 0, 0
	for _, r := range plan.Rows {
		a := r.Default
		if d, ok := decisions[r.Index]; ok {
			a = d
		}
		if r.Status != src.RowInvalid && a != src.ActionSkip {
			take++
			keys += r.NewPasskeys
		}
	}
	if take == 0 {
		if asJSON {
			out, _ := json.MarshalIndent(map[string]any{"result": src.TransferResult{}}, "", "  ")
			fmt.Println(string(out))
			return
		}
		fmt.Println("Nothing to import. Everything in " + name + " is already in your vault or was skipped.")
		return
	}
	if interactive && !yes {
		q := fmt.Sprintf("Import %s", plural(take, "item"))
		if keys > 0 {
			q += " and " + plural(keys, "passkey")
		}
		if keep {
			q += " into their own spaces?"
		} else {
			q += " into " + spaceLabel(space) + "?"
		}
		if ok, cancelled := confirmOrCancel(q+" (Y/n) ", true); cancelled || !ok {
			fmt.Println("Import cancelled. Nothing changed.")
			return
		}
	}

	res, _ := src.ApplyTransfer(vault, set, opt, decisions)
	if res.Changed() > 0 {
		if err := saveCLIVault(vault, masterPassword); err != nil {
			cliFail("Could not save the vault: %v", err)
		}
		src.LogAction("DATA_IMPORTED", fmt.Sprintf("File: %s, Format: %s, Added: %d, Merged: %d, Replaced: %d, Skipped: %d, Passkeys: %d", path, set.Format, res.Added, res.Merged, res.Replaced, res.Skipped, res.PasskeysAdded))
	}
	if asJSON {
		out, _ := json.MarshalIndent(map[string]any{"result": res}, "", "  ")
		fmt.Println(string(out))
		return
	}
	parts := []string{}
	if res.Added > 0 {
		parts = append(parts, fmt.Sprintf("%d added", res.Added))
	}
	if res.Merged > 0 {
		parts = append(parts, fmt.Sprintf("%d merged", res.Merged))
	}
	if res.Replaced > 0 {
		parts = append(parts, fmt.Sprintf("%d replaced", res.Replaced))
	}
	if res.PasskeysAdded > 0 {
		parts = append(parts, plural(res.PasskeysAdded, "passkey"))
	}
	if len(parts) == 0 {
		parts = append(parts, "nothing changed")
	}
	fmt.Println(cOK("✓") + " Imported " + name + ": " + strings.Join(parts, ", ") + cDim(fmt.Sprintf(" (%d skipped)", res.Skipped)))
	for _, r := range res.Renamed {
		fmt.Println("  " + cDim("renamed "+r))
	}
	if len(res.SpacesCreated) > 0 {
		fmt.Println("  " + cDim("new spaces: "+strings.Join(res.SpacesCreated, ", ")))
	}
	for _, e := range res.Errors {
		fmt.Println("  " + cBad("x") + " " + e)
	}
	if res.Changed() > 0 {
		fmt.Println(cDim("Undo the whole import with: pm lgit undo"))
	}
	if !set.Encrypted {
		fmt.Println(cWarn("!") + " Delete " + name + ". It holds your passwords in plain text, and APM does not touch the original.")
	}
}

func containsAction(list []string, a string) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func mustString(s string, _ error) string { return s }

// Export

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export to APM, Credential Exchange, Bitwarden, CSV or text, passkeys included",
		Long: `Export the vault, or part of it.

  pm export                                  APM format, asks to encrypt it
  pm export --format cxf -o vault.cxf.json   FIDO Credential Exchange format
  pm export --format bitwarden --encrypt     Bitwarden, password protected
  pm export --type password,totp --space Work --format csv
  pm export --dry-run                        show what would be exported
  pm export compare backup.json              what changed since that export`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if f, _ := cmd.Flags().GetBool("formats"); f {
				printFormats()
				return
			}
			runExport(cmd)
		},
	}
	f := cmd.Flags()
	f.StringP("output", "o", "", "Output file (default: apm-export-<date>.<ext>)")
	f.StringP("format", "f", "", "apm, cxf, bitwarden, csv or txt (default: from the file name, else apm)")
	f.StringP("password", "p", "", "Encrypt with this password (apm and bitwarden formats)")
	f.Bool("encrypt", false, "Encrypt, asking for the password")
	f.StringP("encrypt-pass", "e", "", "Same as --password")
	_ = f.MarkHidden("encrypt-pass")
	f.Bool("no-encrypt", false, "Write a plain file without asking")
	f.StringSlice("type", nil, "Only these item types (password, totp, note, apikey, ...)")
	f.StringSlice("space", nil, "Only these spaces (use default for the default space)")
	f.Bool("no-passkeys", false, "Leave passkeys out")
	f.Bool("files", false, "Include documents, photos, audio and video (apm format)")
	f.Bool("without-password", false, "Leave secrets out (csv and txt), for a printable inventory")
	f.Bool("dry-run", false, "Show what would be exported and stop")
	f.Bool("force", false, "Overwrite the output file if it exists")
	f.Bool("json", false, "Print the summary as JSON")
	f.Bool("formats", false, "List the formats APM imports and exports")
	cmd.AddCommand(newExportCompareCmd())
	return cmd
}

func exportFormatFor(format, output string, withoutPass bool) string {
	if format != "" {
		return format
	}
	o := strings.ToLower(output)
	switch {
	case strings.HasSuffix(o, ".csv"):
		return "csv"
	case strings.HasSuffix(o, ".txt") || (withoutPass && output == ""):
		return "txt"
	case strings.Contains(o, "cxf"):
		return "cxf"
	case strings.Contains(o, "bitwarden"):
		return "bitwarden"
	}
	return "apm"
}

func runExport(cmd *cobra.Command) {
	f := cmd.Flags()
	output, _ := f.GetString("output")
	format, _ := f.GetString("format")
	password, _ := f.GetString("password")
	if password == "" {
		password, _ = f.GetString("encrypt-pass")
	}
	noEncrypt, _ := f.GetBool("no-encrypt")
	if enc, _ := f.GetBool("encrypt"); enc && password == "" {
		password = "\x00ask"
	}
	types, _ := f.GetStringSlice("type")
	spaces, _ := f.GetStringSlice("space")
	noPasskeys, _ := f.GetBool("no-passkeys")
	files, _ := f.GetBool("files")
	withoutPass, _ := f.GetBool("without-password")
	dry, _ := f.GetBool("dry-run")
	force, _ := f.GetBool("force")
	asJSON, _ := f.GetBool("json")
	interactive := stdinIsTerminal() && !asJSON

	format = exportFormatFor(format, output, withoutPass)
	ex, ok := src.TransferExporterByID(format)
	if !ok {
		cliFail("Unknown format %q. Use apm, cxf, bitwarden, csv or txt (pm export --formats).", format)
	}
	for i, t := range types {
		t = strings.ToLower(strings.TrimSpace(t))
		switch t {
		case "login", "logins", "passwords":
			t = "password"
		case "authenticator", "otp", "2fa":
			t = "totp"
		case "notes":
			t = "note"
		}
		if _, ok := src.ItemTypeByID(t); !ok {
			cliFail("Unknown item type %q.", types[i])
		}
		types[i] = t
	}
	if output == "" {
		output = fmt.Sprintf("apm-export-%s.%s", time.Now().Format("2006-01-02"), ex.Ext)
		if ex.ID == "cxf" {
			output = fmt.Sprintf("apm-export-%s.cxf.json", time.Now().Format("2006-01-02"))
		} else if ex.ID == "bitwarden" {
			output = fmt.Sprintf("apm-bitwarden-export-%s.json", time.Now().Format("2006-01-02"))
		}
	}

	_, vault, _, err := src_unlockVault()
	if err != nil {
		cliFail("%v", err)
	}
	sel := src.ExportSelection{Types: types, Spaces: spaces, Passkeys: !noPasskeys, Files: files}
	opt := src.ExportOptions{Secrets: !withoutPass, VaultName: desktopVaultName(vault)}
	_, items, sum, err := vault.PlanExport(ex.ID, sel, opt)
	if err != nil {
		cliFail("%v", err)
	}
	if !asJSON {
		printExportSummary(ex, sum, output)
	}
	if dry {
		if asJSON {
			out, _ := json.MarshalIndent(map[string]any{"summary": sum, "output": output}, "", "  ")
			fmt.Println(string(out))
		} else {
			fmt.Println(cDim("Dry run. Nothing was written."))
		}
		return
	}
	if len(items) == 0 {
		cliFail("Nothing to export. The selection has no items %s can hold.", ex.Label)
	}
	if _, err := os.Stat(output); err == nil && !force {
		if !interactive {
			cliFail("%s exists. Use --force to overwrite it.", output)
		}
		if ok, cancelled := confirmOrCancel(output+" exists. Overwrite it? (y/N) ", false); cancelled || !ok {
			fmt.Println("Export cancelled.")
			return
		}
	}
	if ex.Encryption {
		if password == "\x00ask" || (password == "" && !noEncrypt && interactive) {
			want := true
			if password == "" {
				var cancelled bool
				if want, cancelled = confirmOrCancel("Encrypt the export with a password? (Y/n) ", true); cancelled {
					fmt.Println("Export cancelled.")
					return
				}
			}
			password = ""
			if want {
				for password == "" {
					p1 := promptHidden("Export password (not your master password): ", "Export cancelled.")
					if p1 == "" && !stdinIsTerminal() {
						cliFail("No export password given.")
					}
					if len(p1) < 8 {
						fmt.Fprintln(os.Stderr, cBad("Use at least 8 characters."))
						continue
					}
					if promptHidden("Repeat it: ", "Export cancelled.") != p1 {
						fmt.Fprintln(os.Stderr, cBad("The passwords do not match."))
						continue
					}
					password = p1
				}
			}
		}
	} else if password != "" && password != "\x00ask" {
		fmt.Fprintln(os.Stderr, cWarn("!")+" "+ex.Label+" files cannot be encrypted. The password is ignored.")
		password = ""
	} else {
		password = ""
	}
	opt.Password = password
	opt.Created = time.Now()
	data, err := ex.Write(items, opt)
	if err != nil {
		cliFail("Export failed: %v", err)
	}
	if err := os.WriteFile(output, data, 0600); err != nil {
		cliFail("Cannot write %s: %v", output, err)
	}
	_ = os.Chmod(output, 0600)
	src.LogAction("DATA_EXPORTED", fmt.Sprintf("File: %s, Format: %s, Items: %d, Passkeys: %d, Encrypted: %t", output, ex.ID, sum.Items, sum.Passkeys, password != ""))
	src.SendAlert(vault, src.LevelAll, "DATA EXPORT", fmt.Sprintf("%d items exported to %s (%s)", sum.Items, output, ex.Label))
	if asJSON {
		sum.Encrypted = password != ""
		out, _ := json.MarshalIndent(map[string]any{"summary": sum, "output": output, "bytes": len(data)}, "", "  ")
		fmt.Println(string(out))
		return
	}
	msg := fmt.Sprintf("%s Exported %s", cOK("✓"), plural(sum.Items, "item"))
	if sum.Passkeys > 0 {
		msg += " and " + plural(sum.Passkeys, "passkey")
	}
	fmt.Println(msg + " to " + output)
	if password != "" {
		fmt.Println(cDim("Encrypted with Argon2id and AES-256-GCM. You need the export password to import it."))
	} else if opt.Secrets {
		fmt.Println(cWarn("!") + " This file is not encrypted. Anyone who can read it can read every exported secret. Delete it when you are done.")
	}
}

func desktopVaultName(v *src.Vault) string {
	if v.Desktop != nil && strings.TrimSpace(v.Desktop.Name) != "" {
		return v.Desktop.Name
	}
	return "Personal vault"
}

func printExportSummary(ex src.TransferExporter, sum src.ExportSummary, output string) {
	fmt.Printf("%s · %s · %s", cBold(output), ex.Label, plural(sum.Items, "item"))
	if sum.Passkeys > 0 {
		fmt.Printf(" · %s", plural(sum.Passkeys, "passkey"))
	}
	fmt.Println()
	types := make([]string, 0, len(sum.ByType))
	for t := range sum.ByType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return sum.ByType[types[i]] > sum.ByType[types[j]] })
	for _, t := range types {
		fmt.Printf("  %s %4d\n", pad(src.TypeLabel(t), 18), sum.ByType[t])
	}
	for _, e := range sum.Excluded {
		fmt.Printf("  %s %s %s\n", cWarn("-"), e.Reason, cDim(fmt.Sprintf("(%d)", e.Count)))
	}
	fmt.Println()
}

func newExportCompareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compare <file>",
		Short: "Compare the vault with an earlier export or backup",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			f := cmd.Flags()
			password, _ := f.GetString("password")
			from, _ := f.GetString("from")
			show, _ := f.GetBool("show-secrets")
			asJSON, _ := f.GetBool("json")
			_, vault, _, err := src_unlockVault()
			if err != nil {
				cliFail("%v", err)
			}
			set, err := readTransfer(args[0], password, from, stdinIsTerminal() && !asJSON)
			if err != nil {
				cliFail("%v", err)
			}
			plan, only := src.CompareTransfer(vault, set, src.PlanOptions{Space: vault.CurrentSpace, KeepSpaces: true})
			if asJSON {
				out, _ := json.MarshalIndent(map[string]any{"file": filepath.Base(args[0]), "formatLabel": set.FormatLabel, "plan": plan, "vaultOnly": only}, "", "  ")
				fmt.Println(string(out))
				return
			}
			s := plan.Summary
			name := filepath.Base(args[0])
			fmt.Printf("%s · %s compared with your vault\n\n", cBold(name), set.FormatLabel)
			fmt.Printf("  %s %s\n", cOK("+"), pad(fmt.Sprintf("%d only in the file", s.New), 28)+cDim("deleted since, or never imported"))
			fmt.Printf("  %s %s\n", cWarn("~"), fmt.Sprintf("%d changed", s.Conflicts+s.Duplicates))
			fmt.Printf("  %s %s\n", cDim("="), fmt.Sprintf("%d the same", s.Identical))
			fmt.Printf("  %s %s\n\n", cAcc("*"), pad(fmt.Sprintf("%d only in your vault", len(only)), 28)+cDim("added since"))
			printRows(plan, nil, []string{src.RowNew}, "Only in the file", show, false)
			printRows(plan, nil, []string{src.RowConflict, src.RowDuplicate}, "Changed", show, true)
			if len(only) > 0 {
				fmt.Println(cBold("Only in your vault"))
				for _, o := range only {
					where := ""
					if o.Space != "" {
						where = cDim(" [" + o.Space + "]")
					}
					fmt.Printf("  %s %s %s%s  %s\n", cAcc("*"), pad(clip(o.Title, 28), 28), pad(src.TypeLabel(o.Type), 14), where, cDim(clip(o.Subtitle, 60)))
				}
				fmt.Println()
			}
			if s.New > 0 {
				fmt.Println(cDim("Bring back what is only in the file with: pm import " + args[0]))
			}
		},
	}
	cmd.Flags().StringP("password", "p", "", "Password of an encrypted export")
	cmd.Flags().String("from", "auto", "Source: auto, 1password, bitwarden, keepass, cxf, apm or csv")
	cmd.Flags().Bool("show-secrets", false, "Show secret values")
	cmd.Flags().Bool("json", false, "Print as JSON")
	return cmd
}
