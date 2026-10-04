package main

import (
	"fmt"
	"strings"

	src "github.com/aaravmaloo/apm/src"
)

// promptLoginExtras asks for the parts of a login beyond the name, username
// and password: website, other websites, notes, the 2FA key and custom fields.
// Only what the user changes ends up in the returned map.
func promptLoginExtras(e src.Entry) map[string]any {
	extra := map[string]any{}
	keepOrClear := func(label, current string) (string, bool) {
		shown := current
		if shown == "" {
			shown = "none"
		}
		fmt.Printf("%s [%s] (blank to keep, - to clear): ", label, shown)
		in := strings.TrimSpace(readInput())
		switch in {
		case "":
			return current, false
		case "-":
			return "", true
		}
		return in, true
	}
	if v, ok := keepOrClear("Website", e.Website); ok {
		extra["website"] = v
	}
	if v, ok := keepOrClear("Other websites, comma separated", strings.Join(e.URLs, ", ")); ok {
		extra["urls"] = v
	}
	if v, ok := keepOrClear("Notes", e.Notes); ok {
		extra["notes"] = v
	}

	totpState := "none"
	if e.TOTP != "" {
		totpState = "set"
	}
	fmt.Printf("2FA setup key or otpauth:// link [%s] (blank to keep, - to remove): ", totpState)
	switch in := strings.TrimSpace(readInput()); in {
	case "":
	case "-":
		extra["totp"] = ""
	default:
		extra["totp"] = in
	}

	fields, changed := promptCustomFields(e.Fields)
	if changed {
		list := make([]any, 0, len(fields))
		for _, cf := range fields {
			list = append(list, map[string]any{"label": cf.Label, "value": cf.Value, "hidden": cf.Hidden})
		}
		extra["fields"] = list
	}
	return extra
}

func promptCustomFields(current []src.CustomField) ([]src.CustomField, bool) {
	out := []src.CustomField{}
	changed := false
	for _, cf := range current {
		shown := cf.Value
		if cf.Hidden {
			shown = "********"
		}
		fmt.Printf("%s [%s] (blank to keep, - to remove): ", cf.Label, shown)
		switch in := strings.TrimSpace(readInput()); in {
		case "":
			out = append(out, cf)
		case "-":
			changed = true
		default:
			cf.Value = in
			out = append(out, cf)
			changed = true
		}
	}
	for {
		fmt.Print("Add a custom field, label (blank to finish): ")
		label := strings.TrimSpace(readInput())
		if label == "" {
			break
		}
		fmt.Printf("%s value: ", label)
		value := strings.TrimSpace(readInput())
		fmt.Print("Hide it like a password? [y/N]: ")
		hidden := strings.HasPrefix(strings.ToLower(strings.TrimSpace(readInput())), "y")
		out = append(out, src.CustomField{Label: label, Value: value, Hidden: hidden})
		changed = true
	}
	return out, changed
}
