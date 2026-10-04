package apm

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type ExportData struct {
	Entries           []Entry             `json:"entries"`
	TOTPEntries       []TOTPEntry         `json:"totp_entries"`
	Tokens            []TokenEntry        `json:"tokens"`
	SecureNotes       []SecureNoteEntry   `json:"secure_notes"`
	APIKeys           []APIKeyEntry       `json:"api_keys"`
	SSHKeys           []SSHKeyEntry       `json:"ssh_keys"`
	WiFiCredentials   []WiFiEntry         `json:"wifi_credentials"`
	RecoveryCodeItems []RecoveryCodeEntry `json:"recovery_codes"`
}

func ExportToJSON(vault *Vault, filename string, encryptPass string) error {
	// Keep the export schema explicit so import/export can evolve independently
	// from the on-disk vault format.
	data := ExportData{
		Entries:           vault.Entries,
		TOTPEntries:       vault.TOTPEntries,
		Tokens:            vault.Tokens,
		SecureNotes:       vault.SecureNotes,
		APIKeys:           vault.APIKeys,
		SSHKeys:           vault.SSHKeys,
		WiFiCredentials:   vault.WiFiCredentials,
		RecoveryCodeItems: vault.RecoveryCodeItems,
	}
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	if encryptPass != "" {
		encrypted, err := EncryptData(bytes, encryptPass)
		if err != nil {
			return err
		}
		return os.WriteFile(filename, encrypted, 0600)
	}

	return os.WriteFile(filename, bytes, 0600)
}

func ExportToCSV(vault *Vault, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	_ = writer.Write([]string{"Type", "Account", "Username/Secret", "Password"})

	for _, e := range vault.Entries {
		_ = writer.Write([]string{"PASSWORD", e.Account, e.Username, e.Password})
	}
	for _, t := range vault.AllTOTPs() {
		_ = writer.Write([]string{"TOTP", t.Account, t.Secret, ""})
	}
	for _, tok := range vault.Tokens {
		_ = writer.Write([]string{"TOKEN", tok.Name, tok.Token, ""})
	}
	for _, n := range vault.SecureNotes {
		_ = writer.Write([]string{"NOTE", n.Name, n.Content, ""})
	}
	for _, k := range vault.APIKeys {
		_ = writer.Write([]string{"API_KEY", k.Name, k.Service, k.Key})
	}
	for _, s := range vault.SSHKeys {
		_ = writer.Write([]string{"SSH_KEY", s.Name, s.PrivateKey, ""})
	}
	for _, w := range vault.WiFiCredentials {
		_ = writer.Write([]string{"WIFI", w.SSID, w.SecurityType, w.Password})
	}
	for _, r := range vault.RecoveryCodeItems {
		_ = writer.Write([]string{"RECOVERY", r.Service, strings.Join(r.Codes, ","), ""})
	}

	return nil
}

func ExportToTXT(vault *Vault, filename string, withoutPassword bool) error {
	var sb strings.Builder
	sb.WriteString("APM Export\n")
	sb.WriteString("==========\n\n")

	sb.WriteString("PASSWORDS:\n")
	for _, e := range vault.Entries {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Account: %s | Username: %s\n", e.Account, e.Username))
		} else {
			sb.WriteString(fmt.Sprintf("Account: %s | Username: %s | Password: %s\n", e.Account, e.Username, e.Password))
		}
	}

	sb.WriteString("\nTOTP:\n")
	for _, t := range vault.AllTOTPs() {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Account: %s\n", t.Account))
		} else {
			sb.WriteString(fmt.Sprintf("Account: %s | Secret: %s\n", t.Account, t.Secret))
		}
	}

	sb.WriteString("\nTOKENS:\n")
	for _, t := range vault.Tokens {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Name: %s\n", t.Name))
		} else {
			sb.WriteString(fmt.Sprintf("Name: %s | Token: %s\n", t.Name, t.Token))
		}
	}

	sb.WriteString("\nSECURE NOTES:\n")
	for _, n := range vault.SecureNotes {
		sb.WriteString(fmt.Sprintf("Name: %s\nContent: %s\n---\n", n.Name, n.Content))
	}

	sb.WriteString("\nAPI KEYS:\n")
	for _, k := range vault.APIKeys {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Name: %s | Service: %s\n", k.Name, k.Service))
		} else {
			sb.WriteString(fmt.Sprintf("Name: %s | Service: %s | Key: %s\n", k.Name, k.Service, k.Key))
		}
	}

	sb.WriteString("\nSSH KEYS:\n")
	for _, s := range vault.SSHKeys {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Name: %s\n", s.Name))
		} else {
			sb.WriteString(fmt.Sprintf("Name: %s\nPrivate Key:\n%s\n---\n", s.Name, s.PrivateKey))
		}
	}

	sb.WriteString("\nWI-FI:\n")
	for _, w := range vault.WiFiCredentials {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("SSID: %s | Security: %s\n", w.SSID, w.SecurityType))
		} else {
			sb.WriteString(fmt.Sprintf("SSID: %s | Security: %s | Password: %s\n", w.SSID, w.SecurityType, w.Password))
		}
	}

	sb.WriteString("\nRECOVERY CODES:\n")
	for _, r := range vault.RecoveryCodeItems {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Service: %s\n", r.Service))
		} else {
			sb.WriteString(fmt.Sprintf("Service: %s | Codes: %s\n", r.Service, strings.Join(r.Codes, ", ")))
		}
	}

	return os.WriteFile(filename, []byte(sb.String()), 0600)
}

func ImportFromJSON(vault *Vault, filename string, decryptPass string) error {
	filename = filepath.Clean(filename)
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	if decryptPass != "" {
		decrypted, err := DecryptData(bytes, decryptPass)
		if err == nil {
			bytes = decrypted
		} else if !json.Valid(bytes) {
			// Data is not valid JSON and decryption failed — likely wrong password.
			return fmt.Errorf("decryption failed: %v (wrong password or corrupted file)", err)
		}
		// If data is valid JSON, assume it wasn't encrypted and the password was
		// provided unnecessarily; fall through to plaintext parsing.
	}

	var data ExportData
	// Prefer the native export shape first before falling back to looser recovery
	// of foreign JSON layouts below.
	if err := json.Unmarshal(bytes, &data); err == nil && (len(data.Entries) > 0 || len(data.TOTPEntries) > 0 || len(data.SecureNotes) > 0 || len(data.APIKeys) > 0 || len(data.SSHKeys) > 0 || len(data.WiFiCredentials) > 0 || len(data.RecoveryCodeItems) > 0) {
		for _, e := range data.Entries {
			_ = vault.AddEntry(e.Account, e.Username, e.Password)
		}
		for _, t := range data.TOTPEntries {
			_ = vault.AddTOTPEntry(t.Account, t.Secret)
		}
		for _, tok := range data.Tokens {
			_ = vault.AddToken(tok.Name, tok.Token, tok.Type)
		}
		for _, n := range data.SecureNotes {
			_ = vault.AddSecureNote(n.Name, n.Content)
		}
		for _, k := range data.APIKeys {
			_ = vault.AddAPIKey(k.Name, k.Service, k.Key)
		}
		for _, s := range data.SSHKeys {
			_ = vault.AddSSHKey(s.Name, s.PrivateKey)
		}
		for _, w := range data.WiFiCredentials {
			_ = vault.AddWiFi(w.SSID, w.Password, w.SecurityType)
		}
		for _, r := range data.RecoveryCodeItems {
			_ = vault.AddRecoveryCode(r.Service, r.Codes)
		}
		return nil
	}

	var raw interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {

		if decryptPass == "" {
			return fmt.Errorf("failed to parse JSON. If this is an encrypted file, please provide the password")
		}
		return err
	}

	if m, ok := raw.(map[string]interface{}); ok && decryptPass != "" {
		dataStr, _ := m["data"].(string)
		saltStr, _ := m["enc_salt"].(string)
		if dataStr != "" && saltStr != "" {

			cipherBytes, _ := DecodeBase64(dataStr)
			if len(cipherBytes) > 0 {
				combined := append([]byte(saltStr), cipherBytes...)
				decrypted, err := DecryptData(combined, decryptPass)
				if err == nil {
					// Some legacy exports wrap the actual payload one level deeper after
					// a passphrase-based envelope.
					var innerData ExportData
					if err := json.Unmarshal(decrypted, &innerData); err == nil && (len(innerData.Entries) > 0 || len(innerData.TOTPEntries) > 0 || len(innerData.SecureNotes) > 0 || len(innerData.APIKeys) > 0 || len(innerData.SSHKeys) > 0 || len(innerData.WiFiCredentials) > 0 || len(innerData.RecoveryCodeItems) > 0) {
						for _, e := range innerData.Entries {
							_ = vault.AddEntry(e.Account, e.Username, e.Password)
						}
						for _, t := range innerData.TOTPEntries {
							_ = vault.AddTOTPEntry(t.Account, t.Secret)
						}
						for _, tok := range innerData.Tokens {
							_ = vault.AddToken(tok.Name, tok.Token, tok.Type)
						}
						for _, n := range innerData.SecureNotes {
							_ = vault.AddSecureNote(n.Name, n.Content)
						}
						for _, k := range innerData.APIKeys {
							_ = vault.AddAPIKey(k.Name, k.Service, k.Key)
						}
						for _, s := range innerData.SSHKeys {
							_ = vault.AddSSHKey(s.Name, s.PrivateKey)
						}
						for _, w := range innerData.WiFiCredentials {
							_ = vault.AddWiFi(w.SSID, w.Password, w.SecurityType)
						}
						for _, r := range innerData.RecoveryCodeItems {
							_ = vault.AddRecoveryCode(r.Service, r.Codes)
						}
						return nil
					}

					bytes = decrypted
					_ = json.Unmarshal(bytes, &raw)
				}
			}
		}
	}

	found := false
	var search func(v interface{})
	search = func(v interface{}) {
		switch m := v.(type) {
		case map[string]interface{}:
			// Walk unknown JSON recursively and accept a small set of common field
			// aliases so imports from other password managers degrade gracefully.
			acc, _ := m["account"].(string)
			if acc == "" {
				acc, _ = m["account_name"].(string)
			}
			if acc == "" {
				acc, _ = m["name"].(string)
			}
			if acc == "" {
				acc, _ = m["label"].(string)
			}

			secret, _ := m["secret"].(string)
			if secret == "" {
				secret, _ = m["secret_key"].(string)
			}

			user, _ := m["username"].(string)
			if user == "" {
				user, _ = m["user"].(string)
			}

			pass, _ := m["password"].(string)
			if pass == "" {
				pass, _ = m["pass"].(string)
			}

			otpauth, _ := m["otpauth"].(string)

			if acc != "" && secret != "" {
				_ = vault.AddTOTPEntry(acc, secret)
				found = true
			} else if acc != "" && (user != "" || pass != "") {
				_ = vault.AddEntry(acc, user, pass)
				found = true
			} else if otpauth != "" && strings.HasPrefix(otpauth, "otpauth://") {
				u, err := url.Parse(otpauth)
				if err == nil {
					label := strings.TrimPrefix(u.Path, "/")
					label = strings.TrimPrefix(label, "totp/")
					label, _ = url.PathUnescape(label)
					sec := u.Query().Get("secret")
					if label != "" && sec != "" {
						_ = vault.AddTOTPEntry(label, sec)
						found = true
					}
				}

			}

			for _, val := range m {
				search(val)
			}
		case []interface{}:
			for _, val := range m {
				search(val)
			}
		}
	}

	search(raw)

	if !found {
		// As a last resort, scan raw strings for embedded otpauth URIs since some
		// exports only preserve QR payloads instead of structured fields.
		content := string(bytes)
		parts := strings.Split(content, "\"")
		for _, s := range parts {
			if strings.HasPrefix(s, "otpauth://") {
				u, err := url.Parse(s)
				if err == nil {
					label := strings.TrimPrefix(u.Path, "/")
					label = strings.TrimPrefix(label, "totp/")
					label, _ = url.PathUnescape(label)
					sec := u.Query().Get("secret")
					if label != "" && sec != "" {
						_ = vault.AddTOTPEntry(label, sec)
						found = true
					}
				}
			}
		}
	}

	if !found {
		return fmt.Errorf("no recognizable password or TOTP entries found in this JSON file. It might be encrypted or use an unsupported format")
	}

	return nil
}

func ImportFromCSV(vault *Vault, filename string) error {
	filename = filepath.Clean(filename)
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	if len(records) == 0 {
		return nil
	}

	colMap := make(map[string]int)
	headerChecked := false

	for _, record := range records {
		if !headerChecked {
			// Accept header-driven imports when present, but still tolerate
			// positional CSV dumps below.
			isHeader := false
			for i, val := range record {
				v := strings.ToLower(strings.TrimSpace(val))
				if v == "type" || v == "account" || v == "username" || v == "password" || v == "secret" {
					colMap[v] = i
					isHeader = true
				}
			}
			if isHeader {
				headerChecked = true
				continue
			}
		}

		if len(record) < 2 {
			continue
		}

		if accIdx, ok := colMap["account"]; ok && accIdx < len(record) {
			acc := strings.TrimSpace(record[accIdx])

			passIdx, hasPass := colMap["password"]
			userIdx, hasUser := colMap["username"]
			secIdx, hasSec := colMap["secret"]

			if hasSec && secIdx < len(record) && strings.TrimSpace(record[secIdx]) != "" {
				_ = vault.AddTOTPEntry(acc, strings.TrimSpace(record[secIdx]))
			} else if hasPass && passIdx < len(record) {
				var u string
				if hasUser && userIdx < len(record) {
					u = strings.TrimSpace(record[userIdx])
				}
				_ = vault.AddEntry(acc, u, strings.TrimSpace(record[passIdx]))
			}
			continue
		}

		if len(record) < 3 {
			continue
		}
		dataType := strings.ToUpper(strings.TrimSpace(record[0]))
		account := strings.TrimSpace(record[1])

		switch dataType {
		case "ENTRY", "PASSWORD":
			if len(record) >= 4 {
				_ = vault.AddEntry(account, strings.TrimSpace(record[2]), strings.TrimSpace(record[3]))
			}
		case "TOTP":
			_ = vault.AddTOTPEntry(account, strings.TrimSpace(record[2]))
		}
	}
	return nil
}

func ImportFromTXT(vault *Vault, filename string) error {
	filename = filepath.Clean(filename)
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "APM Export") || strings.HasPrefix(line, "=") || strings.HasSuffix(line, ":") {
			continue
		}

		if strings.HasPrefix(line, "otpauth://") {
			// Plain-text imports sometimes only carry TOTP URIs copied from QR codes.
			u, err := url.Parse(line)
			if err != nil {
				continue
			}
			label := strings.TrimPrefix(u.Path, "/")
			label = strings.TrimPrefix(label, "totp/")
			label = strings.TrimPrefix(label, "hotp/")

			label, _ = url.PathUnescape(label)

			secret := u.Query().Get("secret")
			if label != "" && secret != "" {
				_ = vault.AddTOTPEntry(label, secret)
			}
			continue
		}

		if strings.Contains(line, "Password:") {

			parts := strings.Split(line, "|")
			var acc, user, pass string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "Account:") {
					acc = strings.TrimPrefix(p, "Account:")
				} else if strings.HasPrefix(p, "Username:") {
					user = strings.TrimPrefix(p, "Username:")
				} else if strings.HasPrefix(p, "Password:") {
					pass = strings.TrimPrefix(p, "Password:")
				}
			}
			if acc != "" {
				_ = vault.AddEntry(strings.TrimSpace(acc), strings.TrimSpace(user), strings.TrimSpace(pass))
			}
		} else if strings.Contains(line, "Secret:") {

			parts := strings.Split(line, "|")
			var acc, secret string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "Account:") {
					acc = strings.TrimPrefix(p, "Account:")
				} else if strings.HasPrefix(p, "Secret:") {
					secret = strings.TrimPrefix(p, "Secret:")
				}
			}
			if acc != "" {
				_ = vault.AddTOTPEntry(strings.TrimSpace(acc), strings.TrimSpace(secret))
			}
		}
	}
	return nil
}
