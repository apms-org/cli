package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
	"golang.org/x/term"
)

// itemDraft holds the edits to one item until they are saved, so a whole edit
// session becomes one update and one entry in the item's version history.
type itemDraft struct {
	v        *src.Vault
	ref      src.VaultItemRef
	kind     itemKind
	f        map[string]any
	custom   []src.CustomField
	passkeys []src.Passkey
	space    string
	linked   string
	changed  map[string]bool
}

func newItemDraft(v *src.Vault, ref src.VaultItemRef) *itemDraft {
	d := &itemDraft{v: v, ref: ref, kind: kindOf(ref), f: v.ItemRecordFields(ref), space: ref.Space, changed: map[string]bool{}}
	if ref.Spec.ID == "password" {
		e := v.Entries[ref.Index]
		d.custom = append([]src.CustomField(nil), e.Fields...)
		d.passkeys = append([]src.Passkey(nil), e.Passkeys...)
		if t, _, ok := newItemLookup(v).loginCode(ref); ok {
			d.linked = itemTitle(t)
		}
	}
	return d
}

func (d *itemDraft) set(key string, value any) {
	d.f[key] = value
	d.changed[key] = true
}

func (d *itemDraft) setCustom(list []src.CustomField) {
	d.custom = list
	d.changed["fields"] = true
}

func (d *itemDraft) setPasskeys(list []src.Passkey) {
	d.passkeys = list
	d.changed["passkeys"] = true
}

func (d *itemDraft) setSpace(space string) {
	if strings.EqualFold(space, "default") {
		space = ""
	}
	d.space = space
	if space == d.ref.Space {
		delete(d.changed, "space")
	} else {
		d.changed["space"] = true
	}
}

func (d *itemDraft) title() string {
	return firstNonEmpty(strings.TrimSpace(toStr(d.f[d.ref.Spec.TitleKey])), d.kind.Label)
}

// save applies the draft the way the desktop app saves an edit, so the
// password policy, favorites and version history behave the same. Passkeys are
// not fields, so they go back on the login afterwards.
func (d *itemDraft) save() (src.VaultItemRef, error) {
	patch := map[string]any{}
	for k := range d.changed {
		switch k {
		case "fields":
			patch[k] = d.custom
		case "passkeys", "space":
		default:
			patch[k] = d.f[k]
		}
	}
	var space *string
	if d.changed["space"] {
		space = &d.space
	}
	ref, err := (&desktopServer{vault: d.v}).updateItem(d.ref.ID, patch, space, true)
	if err != nil {
		return src.VaultItemRef{}, err
	}
	if d.changed["passkeys"] {
		d.v.Entries[ref.Index].Passkeys = d.passkeys
	}
	d.ref = ref
	d.changed = map[string]bool{}
	return ref, nil
}

type editRow struct {
	label   string
	value   string
	field   itemField
	kind    string
	index   int
	changed bool
}

// rows is everything the item holds, one line each: its fields in the desktop
// app's order, each custom field, each passkey and the space.
func (d *itemDraft) rows() []editRow {
	var out []editRow
	for _, fd := range d.kind.Fields {
		if fd.Kind != "custom" {
			out = append(out, editRow{label: fd.Label, value: d.display(fd), field: fd, kind: "field", changed: d.changed[fd.Key]})
			continue
		}
		for i, cf := range d.custom {
			value := cf.Value
			if cf.Hidden && value != "" {
				value = "********"
			}
			out = append(out, editRow{label: firstNonEmpty(cf.Label, "Field"), value: value, kind: "custom", index: i, changed: d.changed["fields"]})
		}
		out = append(out, editRow{label: "+ Add custom field", kind: "add_custom"})
	}
	for i, pk := range d.passkeys {
		out = append(out, editRow{label: "Passkey", value: passkeyLine(pk), kind: "passkey", index: i, changed: d.changed["passkeys"]})
	}
	return append(out, editRow{label: "Space", value: spaceOrDefaultName(d.space), kind: "space", changed: d.changed["space"]})
}

func (d *itemDraft) display(fd itemField) string {
	raw := d.f[fd.Key]
	switch fd.Kind {
	case "totp":
		if strings.TrimSpace(toStr(raw)) != "" {
			return "set"
		}
		if d.linked != "" {
			return fmt.Sprintf("not set, uses Authenticator %q", d.linked)
		}
		return ""
	case "bool":
		if b, _ := raw.(bool); b {
			return "Yes"
		}
		return "No"
	case "file":
		if file, ok := raw.(map[string]any); ok {
			return fileSummary(file)
		}
		return ""
	case "list", "codes":
		list, _ := raw.([]string)
		if fd.Kind == "codes" && len(list) > 0 {
			return "******** " + plural(len(list), "code")
		}
		return strings.Join(list, ", ")
	}
	s := toStr(raw)
	switch {
	case s == "":
		return ""
	case isSecretKind(fd.Kind):
		return "********"
	case fd.Kind == "multiline":
		lines := strings.Split(strings.TrimSpace(s), "\n")
		if len(lines) > 1 {
			return fmt.Sprintf("%s  (+%d lines)", lines[0], len(lines)-1)
		}
		return lines[0]
	}
	return s
}

func (d *itemDraft) changes() int {
	return len(d.changed)
}

// editTerm keeps the terminal raw while the user moves through the editor and
// hands it back for typed answers.
type editTerm struct {
	fd     int
	cooked *term.State
}

const (
	keyNone = iota + 256
	keyUp
	keyDown
	keyEnter
	keyEsc
	keyCtrlC
)

func (t *editTerm) key() int {
	b := make([]byte, 8)
	n, err := os.Stdin.Read(b)
	if err != nil || n == 0 {
		return keyCtrlC
	}
	switch {
	case n >= 3 && b[0] == 27 && (b[1] == '[' || b[1] == 'O'):
		switch b[2] {
		case 'A':
			return keyUp
		case 'B':
			return keyDown
		}
		return keyNone
	case n >= 2 && (b[0] == 224 || b[0] == 0):
		switch b[1] {
		case 72:
			return keyUp
		case 80:
			return keyDown
		}
		return keyNone
	case b[0] == 27:
		return keyEsc
	case b[0] == 3 || b[0] == 4:
		return keyCtrlC
	case b[0] == '\r' || b[0] == '\n':
		return keyEnter
	case b[0] == 'k':
		return keyUp
	case b[0] == 'j':
		return keyDown
	}
	return int(b[0] | 0x20)
}

func (t *editTerm) print(s string) {
	fmt.Print("\033[H\033[J" + strings.ReplaceAll(s, "\n", "\r\n"))
}

func (t *editTerm) withCooked(fn func()) {
	_ = term.Restore(t.fd, t.cooked)
	fn()
	_, _ = term.MakeRaw(t.fd)
}

// say prints below what is already on screen while the terminal is raw.
func (t *editTerm) say(format string, args ...any) {
	fmt.Print(strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", "\r\n"))
}

// line reads one typed answer while the terminal stays raw, so Esc can cancel
// it. Hidden answers are not echoed. ok is false when the user cancelled.
func (t *editTerm) line(hidden bool) (string, bool) {
	var buf []byte
	b := make([]byte, 256)
	for {
		n, err := os.Stdin.Read(b)
		if err != nil || n == 0 {
			return "", false
		}
		for i := 0; i < n; i++ {
			c := b[i]
			switch {
			case c == 27 && i+1 < n && (b[i+1] == '[' || b[i+1] == 'O'):
				// An arrow or other special key: skip its whole sequence.
				for i += 2; i < n && (b[i] < 0x40 || b[i] > 0x7e); i++ {
				}
			case c == 27 || c == 3:
				fmt.Print("\r\n")
				return "", false
			case c == '\r' || c == '\n':
				fmt.Print("\r\n")
				return strings.TrimSpace(string(buf)), true
			case c == 127 || c == 8:
				if len(buf) > 0 {
					_, size := utf8.DecodeLastRune(buf)
					buf = buf[:len(buf)-size]
					if !hidden {
						fmt.Print("\b \b")
					}
				}
			case c == 21:
				if !hidden {
					fmt.Print(strings.Repeat("\b \b", utf8.RuneCount(buf)))
				}
				buf = buf[:0]
			case c >= 32:
				buf = append(buf, c)
				if !hidden {
					_, _ = os.Stdout.Write([]byte{c})
				}
			}
		}
	}
}

// heading clears the screen for a prompt about one part of the item.
func (t *editTerm) heading(title string) {
	t.print(color.New(color.Bold).Sprint(title) + "\n")
}

func (t *editTerm) width() int {
	if w, _, err := term.GetSize(t.fd); err == nil && w > 20 {
		return w
	}
	return 80
}

// pick lets the user choose one option with the arrow keys.
func (t *editTerm) pick(title string, options []string, current string) (string, bool) {
	sel := -1
	for i, o := range options {
		if strings.EqualFold(o, current) {
			sel = i
		}
	}
	if sel < 0 && strings.TrimSpace(current) != "" {
		options = append([]string{current}, options...)
		sel = 0
	}
	if sel < 0 {
		sel = 0
	}
	for {
		var b strings.Builder
		b.WriteString(color.New(color.Bold).Sprint(title) + "\n\n")
		for i, o := range options {
			if i == sel {
				b.WriteString("  \x1b[7m " + o + " \x1b[0m\n")
			} else {
				b.WriteString("   " + o + "\n")
			}
		}
		b.WriteString("\n" + color.New(color.Faint).Sprint("↑↓ move · Enter choose · Esc cancel"))
		t.print(b.String())
		switch t.key() {
		case keyUp:
			if sel > 0 {
				sel--
			}
		case keyDown:
			if sel < len(options)-1 {
				sel++
			}
		case keyEnter:
			return options[sel], true
		case keyEsc, keyCtrlC, 'q':
			return "", false
		}
	}
}

func (t *editTerm) confirm(question string) bool {
	t.print(question + " [y/N] ")
	return t.key() == 'y'
}

func clipRunes(s string, max int) string {
	if max < 2 {
		max = 2
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max-1]) + "…"
}

func (d *itemDraft) render(rows []editRow, sel, width int, status string) string {
	var b strings.Builder
	b.WriteString(color.New(color.Bold).Sprint("Edit "+d.title()) + "\n")
	b.WriteString(color.New(color.Faint).Sprint(d.kind.Label+" · space: "+spaceOrDefaultName(d.space)) + "\n\n")
	w := 0
	for _, r := range rows {
		if n := utf8.RuneCountInString(r.label); n > w {
			w = n
		}
	}
	for i, r := range rows {
		mark := "  "
		if r.changed {
			mark = color.YellowString("• ")
		}
		label := r.label + strings.Repeat(" ", w-utf8.RuneCountInString(r.label))
		value := clipRunes(r.value, width-w-10)
		switch {
		case i == sel:
			b.WriteString(mark + "\x1b[7m " + label + "   " + value + " \x1b[0m\n")
		case r.kind == "add_custom":
			b.WriteString(mark + " " + color.New(color.Faint).Sprint(r.label) + "\n")
		case value == "":
			b.WriteString(mark + " " + label + "   " + color.New(color.Faint).Sprint("empty") + "\n")
		default:
			b.WriteString(mark + " " + color.New(color.Faint).Sprint(label) + "   " + value + "\n")
		}
	}
	b.WriteString("\n")
	if status != "" {
		b.WriteString(color.YellowString(status) + "\n")
	}
	if n := d.changes(); n > 0 {
		b.WriteString(color.YellowString("%s not saved yet.", plural(n, "change")) + "\n")
	}
	keys := "↑↓ move · Enter edit"
	if k := rows[sel].kind; k == "custom" || k == "passkey" {
		keys += " · x remove"
	}
	b.WriteString(color.New(color.Faint).Sprint(keys + " · s save · Esc done"))
	return b.String()
}

// editItemInteractive shows everything an item holds and lets the user pick
// what to change with the arrow keys. Nothing is written until they save.
func editItemInteractive(v *src.Vault, mp string, ref src.VaultItemRef) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		color.Red("Editing needs an interactive terminal.")
		return
	}
	cooked, err := term.MakeRaw(fd)
	if err != nil {
		color.Red("Error entering raw mode: %v", err)
		return
	}
	t := &editTerm{fd: fd, cooked: cooked}
	defer term.Restore(fd, cooked)

	finish := func(msg string) {
		_ = term.Restore(fd, cooked)
		fmt.Print("\033[H\033[J")
		fmt.Println(msg)
	}
	d := newItemDraft(v, ref)
	sel, status := 0, ""
	for {
		rows := d.rows()
		if sel >= len(rows) {
			sel = len(rows) - 1
		}
		t.print(d.render(rows, sel, t.width(), status))
		status = ""
		switch k := t.key(); k {
		case keyUp:
			if sel > 0 {
				sel--
			}
		case keyDown:
			if sel < len(rows)-1 {
				sel++
			}
		case keyEnter:
			status = d.editRow(t, rows[sel])
		case 'x':
			status = d.removeRow(t, rows[sel])
		case 's':
			if d.changes() == 0 {
				status = "Nothing to save."
				continue
			}
			if status = d.commit(mp); status == "" {
				finish(color.GreenString("Saved %s.", itemTitle(d.ref)))
				return
			}
		case keyEsc, keyCtrlC, 'q':
			if d.changes() == 0 {
				finish("No changes.")
				return
			}
			t.print(color.YellowString("Save your %s to %s?", plural(d.changes(), "change"), d.title()) + "\n\n  y  save\n  n  discard them\n  Esc  keep editing")
			switch t.key() {
			case 'y':
				if status = d.commit(mp); status == "" {
					finish(color.GreenString("Saved %s.", itemTitle(d.ref)))
					return
				}
			case 'n':
				finish("Discarded your changes.")
				return
			}
		}
	}
}

// commit saves the draft and the vault. It returns why that failed, or "".
func (d *itemDraft) commit(mp string) string {
	var removed []src.Passkey
	if d.changed["passkeys"] {
		keep := map[string]bool{}
		for _, pk := range d.passkeys {
			keep[pk.CredentialID] = true
		}
		for _, pk := range d.v.Entries[d.ref.Index].Passkeys {
			if !keep[pk.CredentialID] {
				removed = append(removed, pk)
			}
		}
	}
	ref, err := d.save()
	if err != nil {
		return "Not saved: " + err.Error()
	}
	data, err := src.EncryptVault(d.v, mp)
	if err == nil {
		err = src.SaveVault(vaultPath, data)
	}
	if errors.Is(err, src.ErrVaultNewer) {
		return vaultNewerMessage
	} else if err != nil {
		return "Error saving vault: " + err.Error()
	}
	for _, pk := range removed {
		src.LogAction("PASSKEY_DELETED", fmt.Sprintf("credential=%s entry=%s", pk.CredentialID, ref.Title))
	}
	src.SendAlert(d.v, src.LevelAll, "ENTRY MODIFIED", fmt.Sprintf("Modified entry: %s (%s)", ref.Title, d.kind.Label))
	return ""
}

func (d *itemDraft) editRow(t *editTerm, r editRow) string {
	switch r.kind {
	case "space":
		if s, ok := t.pick("Move "+d.title()+" to space", sortedSpaces(d.v, d.space), spaceOrDefaultName(d.space)); ok {
			d.setSpace(s)
		}
		return ""
	case "passkey":
		return d.renamePasskey(t, r.index)
	case "custom", "add_custom":
		return d.promptCustom(t, r.index, r.kind == "add_custom")
	}
	fd := r.field
	current := toStr(d.f[fd.Key])
	switch fd.Kind {
	case "bool":
		b, _ := d.f[fd.Key].(bool)
		d.set(fd.Key, !b)
		return ""
	case "select":
		if s, ok := t.pick(d.title()+" › "+fd.Label, fd.Options, current); ok && s != current {
			d.set(fd.Key, s)
		}
		return ""
	case "multiline", "secretBlock":
		var status string
		t.withCooked(func() {
			content, err := captureNoteContent(d.v, d.title()+" › "+fd.Label, current)
			switch {
			case err != nil:
				status = "Kept the old " + strings.ToLower(fd.Label) + "."
			case fd.Required && strings.TrimSpace(content) == "":
				status = fd.Label + " can't be empty."
			case content != current:
				d.set(fd.Key, content)
			}
		})
		return status
	}
	return d.promptField(t, fd)
}

// promptField asks for a new value of a field typed on one line. It returns
// why the answer was not taken, or "". Esc leaves the field as it was.
func (d *itemDraft) promptField(t *editTerm, fd itemField) string {
	t.heading(d.title() + " › " + fd.Label)
	now := d.display(fd)
	keep := "Enter keeps it"
	if now == "" {
		now, keep = "empty", "Enter leaves it empty"
	}
	if !fd.Required && now != "empty" {
		keep += ", - clears it"
	}
	keep += ", Esc cancels"
	t.say("%s\n", color.New(color.Faint).Sprint("Now: "+now))
	clear := func(in string) (bool, string) {
		if in != "-" {
			return false, ""
		}
		if fd.Required {
			return true, fd.Label + " can't be empty."
		}
		d.set(fd.Key, emptyValue(fd))
		return true, ""
	}

	switch fd.Kind {
	case "password", "secret":
		t.say("Type the new %s. It stays hidden. %s.\n> ", strings.ToLower(fd.Label), keep)
		in, ok := t.line(true)
		if !ok || in == "" {
			return ""
		}
		if done, status := clear(in); done {
			return status
		}
		if fd.Kind == "password" {
			t.say("Type it again.\n> ")
			again, ok := t.line(true)
			if !ok {
				return ""
			}
			if again != in {
				return "The two entries didn't match. " + fd.Label + " not changed."
			}
		}
		d.set(fd.Key, in)
	case "totp":
		t.say("Paste the setup key or otpauth:// link the site shows. %s.\n> ", keep)
		in, ok := t.line(false)
		if !ok || in == "" {
			return ""
		}
		if done, status := clear(in); done {
			return status
		}
		secret, problem := src.TOTPSecretFrom(in)
		if problem != "" {
			return "That setup key doesn't work: " + problem
		}
		d.set(fd.Key, secret)
	case "file":
		t.say("Type or drop the path of the file to put in its place. Enter keeps it, Esc cancels.\n> ")
		in, ok := t.line(false)
		if !ok || in == "" {
			return ""
		}
		path := strings.ReplaceAll(strings.Trim(in, `"'`), `\ `, " ")
		if strings.HasPrefix(path, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				path = filepath.Join(home, path[2:])
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "Couldn't read that file: " + err.Error()
		}
		d.set(fd.Key, map[string]any{"name": filepath.Base(path), "size": len(data), "data": base64.StdEncoding.EncodeToString(data)})
	case "list", "codes":
		t.say("Type them separated by commas. %s.\n> ", keep)
		in, ok := t.line(false)
		if !ok || in == "" {
			return ""
		}
		if done, status := clear(in); done {
			return status
		}
		var list []string
		for _, s := range strings.Split(in, ",") {
			if s = strings.TrimSpace(s); s != "" {
				list = append(list, s)
			}
		}
		d.set(fd.Key, list)
	default:
		t.say("Type the new %s. %s.\n> ", strings.ToLower(fd.Label), keep)
		in, ok := t.line(false)
		if !ok || in == "" {
			return ""
		}
		if done, status := clear(in); done {
			return status
		}
		if fd.Kind == "date" {
			if _, err := time.Parse("2006-01-02", in); err != nil {
				return fd.Label + " must be a date like 2027-03-31."
			}
		}
		d.set(fd.Key, in)
	}
	return ""
}

func emptyValue(fd itemField) any {
	switch fd.Kind {
	case "list", "codes":
		return []string{}
	}
	return ""
}

// promptCustom edits custom field i, or adds one. Esc at any step leaves the
// fields as they were.
func (d *itemDraft) promptCustom(t *editTerm, i int, add bool) string {
	cf := src.CustomField{}
	if add {
		t.heading(d.title() + " › New custom field")
		t.say("Label, like PIN or Security answer. Esc cancels.\n> ")
		label, ok := t.line(false)
		if !ok || label == "" {
			return ""
		}
		cf.Label = label
		t.say("Hide it like a password? [y/N] ")
		in, ok := t.line(false)
		if !ok {
			return ""
		}
		cf.Hidden = strings.HasPrefix(strings.ToLower(in), "y")
	} else {
		cf = d.custom[i]
		t.heading(d.title() + " › " + firstNonEmpty(cf.Label, "Field"))
		t.say("%s\n", color.New(color.Faint).Sprint("Enter keeps each answer, Esc cancels."))
		t.say("Label [%s]: ", cf.Label)
		in, ok := t.line(false)
		if !ok {
			return ""
		}
		if in != "" {
			cf.Label = in
		}
		hide := "y/N"
		if cf.Hidden {
			hide = "Y/n"
		}
		t.say("Hide it like a password? [%s] ", hide)
		if in, ok = t.line(false); !ok {
			return ""
		}
		switch in = strings.ToLower(in); {
		case strings.HasPrefix(in, "y"):
			cf.Hidden = true
		case strings.HasPrefix(in, "n"):
			cf.Hidden = false
		}
	}
	switch {
	case cf.Hidden && add:
		t.say("Value (hidden): ")
	case cf.Hidden:
		t.say("Value (hidden): ")
	case add:
		t.say("Value: ")
	default:
		t.say("Value [%s]: ", cf.Value)
	}
	value, ok := t.line(cf.Hidden)
	if !ok {
		return ""
	}
	if value != "" || add {
		cf.Value = value
	}
	list := append([]src.CustomField(nil), d.custom...)
	if add {
		list = append(list, cf)
	} else if list[i] == cf {
		return ""
	} else {
		list[i] = cf
	}
	d.setCustom(list)
	return ""
}

func (d *itemDraft) renamePasskey(t *editTerm, i int) string {
	pk := d.passkeys[i]
	t.heading(d.title() + " › Passkey for " + pk.RPID)
	t.say("%s\n", color.New(color.Faint).Sprint(passkeyLine(pk)))
	t.say("Give it a name, like the device it was made on. Enter keeps it")
	if pk.Label != "" {
		t.say(", - clears it")
	}
	t.say(", Esc cancels.\n> ")
	in, ok := t.line(false)
	label := pk.Label
	switch {
	case !ok || in == "":
	case in == "-":
		label = ""
	default:
		label = clipRunes(in, 120)
	}
	if label == pk.Label {
		return ""
	}
	list := append([]src.Passkey(nil), d.passkeys...)
	list[i].Label = label
	d.setPasskeys(list)
	return ""
}

func (d *itemDraft) removeRow(t *editTerm, r editRow) string {
	switch r.kind {
	case "custom":
		list := append([]src.CustomField(nil), d.custom[:r.index]...)
		d.setCustom(append(list, d.custom[r.index+1:]...))
		return "Removed " + r.label + "."
	case "passkey":
		pk := d.passkeys[r.index]
		if !t.confirm(fmt.Sprintf("Remove the %s passkey? Once you save, you can't sign in to %s with it.", pk.RPID, pk.RPID)) {
			return ""
		}
		list := append([]src.Passkey(nil), d.passkeys[:r.index]...)
		d.setPasskeys(append(list, d.passkeys[r.index+1:]...))
		return "Removed the " + pk.RPID + " passkey."
	}
	return ""
}
