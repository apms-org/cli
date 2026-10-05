package apm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpMaxPasswordLength = 256

var mcpToolPermissions = []string{
	"list_vault",
	"get_entry",
	"search_vault",
	"decrypt_entry",
	"get_totp",
	"add_entry",
	"delete_entry",
	"edit_entry",
	"manage_profiles",
	"manage_spaces",
	"cloud_config",
	"get_history",
	"generate_password",
	"cloud_sync",
	"get_audit_logs",
	"tx_list",
	"tx_abort",
}

var legacyMCPScopePermissions = map[string][]string{
	"read": {
		"list_vault",
		"search_vault",
	},
	"secrets": {
		"get_entry",
		"decrypt_entry",
		"get_totp",
	},
	"write": {
		"add_entry",
		"delete_entry",
		"edit_entry",
		"manage_spaces",
		"cloud_sync",
	},
	"admin": {
		"manage_profiles",
		"cloud_config",
		"get_history",
		"get_audit_logs",
	},
}

func MCPToolPermissions() []string {
	out := make([]string, len(mcpToolPermissions))
	copy(out, mcpToolPermissions)
	return out
}

func BuildMCPServerConfigWithToken(token string) map[string]interface{} {
	exe, _ := os.Executable()
	if exe == "" {
		exe = "pm"
	}

	args := []interface{}{"mcp", "serve"}
	if token != "" {
		args = append(args, "--token", token)
	}

	if runtime.GOOS == "windows" {
		// Windows MCP clients typically expect a shell entry point rather than
		// invoking the binary directly.
		return map[string]interface{}{
			"command": "cmd",
			"args":    append([]interface{}{"/c", exe}, args...),
			"env":     map[string]string{},
		}
	}

	return map[string]interface{}{
		"command": exe,
		"args":    args,
		"env":     map[string]string{},
	}
}

func FindMCPConfigFiles() []string {
	var files []string
	home, _ := os.UserHomeDir()

	// Probe the common config locations used by supported MCP clients instead of
	// forcing users to wire APM into each one manually.
	paths := []string{
		filepath.Join(os.Getenv("APPDATA"), "Claude", "mcp_config.json"),
		filepath.Join(os.Getenv("APPDATA"), "Cursor", "mcp.json"),
		filepath.Join(os.Getenv("APPDATA"), "Code", "User", "mcp.json"),
		filepath.Join(os.Getenv("APPDATA"), "Cursor", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
		filepath.Join(os.Getenv("APPDATA"), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
		filepath.Join(home, "Library", "Application Support", "Claude", "mcp_config.json"),
		filepath.Join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
		filepath.Join(home, ".config", "Claude", "mcp_config.json"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	return files
}

func UpdateMCPConfigWithToken(filePath, token string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var config map[string]interface{}
	if len(strings.TrimSpace(string(data))) == 0 {
		config = make(map[string]interface{})
	} else if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	mcpServers, ok := config["mcpServers"].(map[string]interface{})
	if !ok {
		// Some clients start from an empty or partially unrelated config file.
		mcpServers = make(map[string]interface{})
	}

	mcpServers["apm"] = BuildMCPServerConfigWithToken(token)
	config["mcpServers"] = mcpServers

	newData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, newData, 0600)
}

type MCPAuthConfig struct {
	Tokens map[string]MCPToken `json:"tokens"`
}

type MCPToken struct {
	Name        string    `json:"name"`
	Token       string    `json:"token"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	UsageCount  int       `json:"usage_count"`
}

func getMCPConfigFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	if err := os.MkdirAll(apmDir, 0700); err != nil {
		// Return a best-effort path; the caller will surface the write error.
	}
	return filepath.Join(apmDir, "mcp_auth.json")
}

func LoadMCPConfig() (*MCPAuthConfig, error) {
	file := getMCPConfigFile()
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return &MCPAuthConfig{Tokens: make(map[string]MCPToken)}, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var config MCPAuthConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if config.Tokens == nil {
		config.Tokens = make(map[string]MCPToken)
	}
	return &config, nil
}

func SaveMCPConfig(config *MCPAuthConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getMCPConfigFile(), data, 0600)
}

func GenerateMCPToken(name string, permissions []string, expiryMinutes int) (string, error) {
	// Tokens are stored by value so each issued credential keeps its own audit
	// metadata even after the caller loses the plaintext string.
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "apm_mcp_" + hex.EncodeToString(b)

	config, err := LoadMCPConfig()
	if err != nil {
		return "", err
	}

	expiresAt := time.Time{}
	if expiryMinutes > 0 {
		expiresAt = time.Now().Add(time.Duration(expiryMinutes) * time.Minute)
	}

	config.Tokens[token] = MCPToken{
		Name:        name,
		Token:       token,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
	}

	if err := SaveMCPConfig(config); err != nil {
		return "", err
	}

	LogAction("MCP_TOKEN_CREATED", fmt.Sprintf("Created token '%s'", name))
	return token, nil
}

func RevokeMCPToken(query string) (bool, error) {
	config, err := LoadMCPConfig()
	if err != nil {
		return false, err
	}

	if _, ok := config.Tokens[query]; ok {
		delete(config.Tokens, query)
		SaveMCPConfig(config)
		LogAction("MCP_TOKEN_REVOKED", "Revoked token by ID")
		return true, nil
	}

	for t, data := range config.Tokens {
		if data.Name == query {
			delete(config.Tokens, t)
			SaveMCPConfig(config)
			LogAction("MCP_TOKEN_REVOKED", fmt.Sprintf("Revoked token '%s'", query))
			return true, nil
		}
	}

	return false, nil
}

func ListMCPTokens() ([]MCPToken, error) {
	config, err := LoadMCPConfig()
	if err != nil {
		return nil, err
	}
	var list []MCPToken
	for _, t := range config.Tokens {
		list = append(list, t)
	}
	return list, nil
}

// requestMCPApproval queues a vault change as a pending transaction. Only the
// person at the computer can commit it; nothing an MCP client sends can.
func requestMCPApproval(tokenName, tool string, args json.RawMessage, preview string) *mcp.CallToolResult {
	tx, err := CreateMCPTransaction(tokenName, tool, args, preview, 15*time.Minute)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Transaction error: %v", err)}}}
	}
	LogAction("MCP_TX_REQUESTED", fmt.Sprintf("Token '%s' requested: %s", tokenName, preview))
	msg := fmt.Sprintf("Waiting for approval: %s\nRequest %s expires at %s. The user approves or rejects it in the APM app (Settings > AI access). Nothing changes until they approve. Call tx_list to see whether it was approved.", preview, tx.ID, tx.ExpiresAt.Format(time.RFC3339))
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

func StartMCPServer(token string, vaultPath string, transport mcp.Transport) error {
	config, err := LoadMCPConfig()
	if err != nil {
		return err
	}

	mcpToken, ok := config.Tokens[token]
	if !ok {
		fmt.Printf("DEBUG: Token mismatch. Wanted: %s, have tokens: %v\n", token, config.Tokens)
		LogAction("MCP_AUTH_FAILED", "Invalid token used")
		return errors.New("invalid or revoked MCP token")
	}

	if !mcpToken.ExpiresAt.IsZero() && time.Now().After(mcpToken.ExpiresAt) {
		LogAction("MCP_AUTH_FAILED", fmt.Sprintf("Expired token '%s' used", mcpToken.Name))
		return errors.New("token expired")
	}

	mcpToken.LastUsedAt = time.Now()
	mcpToken.UsageCount++
	config.Tokens[token] = mcpToken
	SaveMCPConfig(config)
	// Expose the execution context to downstream audit and policy layers so MCP
	// actions are attributable without special casing every call site.
	_ = os.Setenv("APM_CONTEXT", "mcp")
	_ = os.Setenv("APM_ACTOR", "AI")

	s := mcp.NewServer(&mcp.Implementation{
		Name:    "APM-Server",
		Version: "1.3.0",
	}, nil)

	s.AddTool(&mcp.Tool{
		Name:        "list_vault",
		Description: "List all entries in the vault by category",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "list_vault") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}

		var sb strings.Builder
		sb.WriteString("Vault Content Overview:\n")

		addSection := func(title string, items interface{}, nameField string) {
			val := reflect.ValueOf(items)
			if val.Kind() == reflect.Slice && val.Len() > 0 {
				// The MCP schema spans many entry types, so reflection keeps this
				// inventory view in sync without hand-writing one formatter per slice.
				sb.WriteString(fmt.Sprintf("\n[%s]\n", title))
				for i := 0; i < val.Len(); i++ {
					item := val.Index(i)
					if item.Kind() == reflect.Struct {
						f := item.FieldByName(nameField)
						if f.IsValid() {
							sb.WriteString("- " + f.String() + "\n")
						}
					}
				}
			}
		}

		addSection("Passwords", vault.Entries, "Account")
		addSection("TOTP", vault.TOTPEntries, "Account")
		addSection("Secure Notes", vault.SecureNotes, "Name")
		addSection("API Keys", vault.APIKeys, "Name")
		addSection("SSH Keys", vault.SSHKeys, "Name")
		addSection("WiFi Credentials", vault.WiFiCredentials, "SSID")
		addSection("Recovery Codes", vault.RecoveryCodeItems, "Service")
		addSection("Certificates", vault.Certificates, "Label")
		addSection("Banking Items", vault.BankingItems, "Label")
		addSection("Documents", vault.Documents, "Name")
		addSection("Medical Records", vault.MedicalRecords, "Label")
		addSection("Travel Documents", vault.TravelDocs, "Label")
		addSection("Gov IDs", vault.GovIDs, "Name")
		addSection("Contacts", vault.Contacts, "Name")
		addSection("Cloud Credentials", vault.CloudCredentialsItems, "Label")
		addSection("K8s Secrets", vault.K8sSecrets, "Name")
		addSection("Docker Registries", vault.DockerRegistries, "Name")
		addSection("SSH Configs", vault.SSHConfigs, "Alias")
		addSection("CI/CD Secrets", vault.CICDSecrets, "Name")
		addSection("Licenses", vault.SoftwareLicenses, "ProductName")
		addSection("Contracts", vault.LegalContracts, "Name")
		addSection("Tokens", vault.Tokens, "Name")
		addSection("Audio Files", vault.AudioFiles, "Name")
		addSection("Video Files", vault.VideoFiles, "Name")
		addSection("Photo Files", vault.PhotoFiles, "Name")

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "get_entry",
		Description: "Get the full details (including secrets) for any vault entry by name. You can optionally specify a category to narrow down the search.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":     map[string]any{"type": "string"},
				"category": map[string]any{"type": "string", "description": "Optional category hint (e.g., 'password', 'totp', 'banking', 'recovery_code', etc.)"},
			},
			"required": []string{"name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "get_entry") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}

		var foundItem interface{}
		var itemType string

		searchIn := func(items interface{}, typeName string, nameField string) bool {
			if args.Category != "" && !strings.Contains(strings.ToLower(typeName), strings.ToLower(args.Category)) && !strings.Contains(strings.ToLower(args.Category), strings.ToLower(typeName)) {
				return false
			}
			val := reflect.ValueOf(items)
			for i := 0; i < val.Len(); i++ {
				item := val.Index(i)
				f := item.FieldByName(nameField)
				if f.IsValid() && f.String() == args.Name {
					foundItem = item.Interface()
					itemType = typeName
					return true
				}
			}
			return false
		}

		found := searchIn(vault.Entries, "Password", "Account") ||
			searchIn(vault.TOTPEntries, "TOTP", "Account") ||
			searchIn(vault.SecureNotes, "Secure Note", "Name") ||
			searchIn(vault.APIKeys, "API Key", "Name") ||
			searchIn(vault.SSHKeys, "SSH Key", "Name") ||
			searchIn(vault.WiFiCredentials, "WiFi", "SSID") ||
			searchIn(vault.RecoveryCodeItems, "Recovery Code", "Service") ||
			searchIn(vault.Certificates, "Certificate", "Label") ||
			searchIn(vault.BankingItems, "Banking", "Label") ||
			searchIn(vault.Documents, "Document", "Name") ||
			searchIn(vault.MedicalRecords, "Medical Record", "Label") ||
			searchIn(vault.TravelDocs, "Travel", "Label") ||
			searchIn(vault.GovIDs, "Gov ID", "Name") ||
			searchIn(vault.Contacts, "Contact", "Name") ||
			searchIn(vault.CloudCredentialsItems, "Cloud", "Label") ||
			searchIn(vault.K8sSecrets, "K8s Secret", "Name") ||
			searchIn(vault.DockerRegistries, "Docker", "Name") ||
			searchIn(vault.SSHConfigs, "SSH Config", "Alias") ||
			searchIn(vault.CICDSecrets, "CI/CD", "Name") ||
			searchIn(vault.SoftwareLicenses, "License", "ProductName") ||
			searchIn(vault.LegalContracts, "Contract", "Name") ||
			searchIn(vault.Tokens, "Token", "Name") ||
			searchIn(vault.AudioFiles, "Audio", "Name") ||
			searchIn(vault.VideoFiles, "Video", "Name") ||
			searchIn(vault.PhotoFiles, "Photo", "Name")

		if !found {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Entry not found"}}}, nil
		}

		jsonData, _ := json.MarshalIndent(foundItem, "", "  ")

		ephemeralKey := make([]byte, 32)
		if _, err := rand.Read(ephemeralKey); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Failed to generate ephemeral key: %v", err)}}}, nil
		}
		ciphertext, err := encryptEpisodic(jsonData, ephemeralKey)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Failed to encrypt entry: %v", err)}}}, nil
		}
		tempPath, err := writeToTemp(ciphertext)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Failed to write temp file: %v", err)}}}, nil
		}
		// Schedule cleanup in case decrypt_entry is never called
		go func() {
			time.Sleep(5 * time.Minute)
			os.Remove(tempPath)
		}()

		LogAction("MCP_ENTRY_ACCESSED", fmt.Sprintf("Token '%s' accessed entry '%s' (%s)", mcpToken.Name, args.Name, itemType))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Data for %s '%s' encrypted at %s. Reference: %s. Use decrypt_entry to view.", itemType, args.Name, tempPath, hex.EncodeToString(ephemeralKey))}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "search_vault",
		Description: "Search for a keyword across all vault entries and categories",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
			"required": []string{"query"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "search_vault") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Query string `json:"query"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		var results []string
		searchTerm := strings.ToLower(args.Query)

		searchSlice := func(items interface{}, typeName string) {
			val := reflect.ValueOf(items)
			for i := 0; i < val.Len(); i++ {
				item := val.Index(i)
				data, _ := json.Marshal(item.Interface())
				if strings.Contains(strings.ToLower(string(data)), searchTerm) {
					results = append(results, fmt.Sprintf("[%s] %v", typeName, item.Interface()))
				}
			}
		}

		searchSlice(vault.Entries, "Password")
		searchSlice(vault.TOTPEntries, "TOTP")
		searchSlice(vault.SecureNotes, "Note")
		searchSlice(vault.APIKeys, "APIKey")
		searchSlice(vault.SSHKeys, "SSHKey")
		searchSlice(vault.WiFiCredentials, "WiFi")
		searchSlice(vault.RecoveryCodeItems, "RecoveryCode")
		searchSlice(vault.BankingItems, "Banking")
		searchSlice(vault.GovIDs, "GovID")
		searchSlice(vault.MedicalRecords, "Medical")
		searchSlice(vault.TravelDocs, "Travel")
		searchSlice(vault.Documents, "Document")
		searchSlice(vault.Contacts, "Contact")
		searchSlice(vault.Tokens, "Token")
		searchSlice(vault.AudioFiles, "Audio")
		searchSlice(vault.VideoFiles, "Video")
		searchSlice(vault.PhotoFiles, "Photo")

		if len(results) == 0 {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "No matches found"}}}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(results, "\n")}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "decrypt_entry",
		Description: "Decrypt an entry using a provided reference key (from get_entry)",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":      map[string]any{"type": "string"},
				"reference": map[string]any{"type": "string"},
			},
			"required": []string{"path", "reference"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "decrypt_entry") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Path      string `json:"path"`
			Reference string `json:"reference"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		ciphertext, err := os.ReadFile(args.Path)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Failed to read encrypted file"}}}, nil
		}

		key, err := hex.DecodeString(args.Reference)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Invalid reference key"}}}, nil
		}

		plaintext, err := decryptEpisodic(ciphertext, key)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Decryption failed"}}}, nil
		}

		os.Remove(args.Path)

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(plaintext)}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "get_totp",
		Description: "Get the current TOTP code for a vault entry",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{"type": "string"},
			},
			"required": []string{"name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "get_totp") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Name string `json:"name"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		for _, e := range vault.AllTOTPs() {
			if e.Account == args.Name {
				code, _ := GenerateTOTP(e.Secret)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("TOTP Code for %s: %s", args.Name, code)}}}, nil
			}
		}

		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "TOTP Account not found"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "add_entry",
		Description: "Request a new vault entry. The entry is added only after the user approves the request in the APM app.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"type": map[string]any{"type": "string", "enum": []string{
					"password", "totp", "token", "note", "api_key", "ssh_key", "wifi", "recovery_code", "certificate", "banking",
					"document", "gov_id", "medical", "travel", "contact", "cloud", "k8s_secret", "docker", "ssh_config", "cicd",
					"license", "contract", "audio", "video", "photo",
				}},
				"name":          map[string]any{"type": "string"},
				"username":      map[string]any{"type": "string"},
				"password":      map[string]any{"type": "string"},
				"secret":        map[string]any{"type": "string"},
				"content":       map[string]any{"type": "string"},
				"space":         map[string]any{"type": "string"},
				"service":       map[string]any{"type": "string"},
				"key":           map[string]any{"type": "string"},
				"token_val":     map[string]any{"type": "string"},
				"token_type":    map[string]any{"type": "string"},
				"ssid":          map[string]any{"type": "string"},
				"security":      map[string]any{"type": "string"},
				"router_ip":     map[string]any{"type": "string"},
				"codes":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"issuer":        map[string]any{"type": "string"},
				"expiry":        map[string]any{"type": "string", "description": "YYYY-MM-DD or standard string"},
				"label":         map[string]any{"type": "string"},
				"bank_type":     map[string]any{"type": "string"},
				"details":       map[string]any{"type": "string"},
				"cvv":           map[string]any{"type": "string"},
				"id_number":     map[string]any{"type": "string"},
				"id_type":       map[string]any{"type": "string"},
				"full_name":     map[string]any{"type": "string"},
				"insurance_id":  map[string]any{"type": "string"},
				"prescriptions": map[string]any{"type": "string"},
				"allergies":     map[string]any{"type": "string"},
				"ticket_number": map[string]any{"type": "string"},
				"booking_code":  map[string]any{"type": "string"},
				"loyalty":       map[string]any{"type": "string"},
				"phone":         map[string]any{"type": "string"},
				"email":         map[string]any{"type": "string"},
				"address":       map[string]any{"type": "string"},
				"emergency":     map[string]any{"type": "boolean"},
				"access_key":    map[string]any{"type": "string"},
				"secret_key":    map[string]any{"type": "string"},
				"region":        map[string]any{"type": "string"},
				"account_id":    map[string]any{"type": "string"},
				"role":          map[string]any{"type": "string"},
				"cluster_url":   map[string]any{"type": "string"},
				"namespace":     map[string]any{"type": "string"},
				"registry_url":  map[string]any{"type": "string"},
				"alias":         map[string]any{"type": "string"},
				"host":          map[string]any{"type": "string"},
				"port":          map[string]any{"type": "string"},
				"key_path":      map[string]any{"type": "string"},
				"fingerprint":   map[string]any{"type": "string"},
				"webhook":       map[string]any{"type": "string"},
				"env_vars":      map[string]any{"type": "string"},
				"product_name":  map[string]any{"type": "string"},
				"serial_key":    map[string]any{"type": "string"},
				"activation":    map[string]any{"type": "string"},
				"summary":       map[string]any{"type": "string"},
				"parties":       map[string]any{"type": "string"},
				"signed_date":   map[string]any{"type": "string"},
				"file_name":     map[string]any{"type": "string"},
				"tags":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"type", "name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "add_entry") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args MCPAddEntryArgs
		json.Unmarshal(req.Params.Arguments, &args)

		return requestMCPApproval(mcpToken.Name, "add_entry", req.Params.Arguments, fmt.Sprintf("Add %s entry '%s' in space '%s'", args.Type, args.Name, args.Space)), nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "delete_entry",
		Description: "Request removal of a vault entry. The entry is removed only after the user approves the request in the APM app.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
			"required":   []string{"name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "delete_entry") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Name string `json:"name"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		return requestMCPApproval(mcpToken.Name, "delete_entry", req.Params.Arguments, fmt.Sprintf("Delete entry '%s'", args.Name)), nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "edit_entry",
		Description: "Request a change to an existing vault entry. The change is made only after the user approves the request in the APM app.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"type": map[string]any{"type": "string", "enum": []string{
					"password", "totp", "token", "note", "api_key", "ssh_key", "wifi", "recovery_code", "certificate", "banking",
					"document", "gov_id", "medical", "travel", "contact", "cloud", "k8s_secret", "docker", "ssh_config", "cicd",
					"license", "contract", "audio", "video", "photo",
				}},
				"name":     map[string]any{"type": "string"},
				"username": map[string]any{"type": "string"},
				"password": map[string]any{"type": "string"},
				"secret":   map[string]any{"type": "string"},
				"content":  map[string]any{"type": "string"},
				"space":    map[string]any{"type": "string"},
			},
			"required": []string{"type", "name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "edit_entry") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args MCPEditEntryArgs
		json.Unmarshal(req.Params.Arguments, &args)

		return requestMCPApproval(mcpToken.Name, "edit_entry", req.Params.Arguments, fmt.Sprintf("Edit %s entry '%s' in space '%s'", args.Type, args.Name, args.Space)), nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "manage_profiles",
		Description: "List or configure encryption profiles",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":  map[string]any{"type": "string", "enum": []string{"list", "set"}},
				"profile": map[string]any{"type": "string"},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "manage_profiles") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Action  string `json:"action"`
			Profile string `json:"profile"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}
		if r := mcpRefuseNewer(vault); r != nil {
			return r, nil
		}

		if args.Action == "list" {
			profiles := []string{}
			for name := range Profiles {
				profiles = append(profiles, name)
			}
			sort.Strings(profiles)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Current Profile: %s\nAvailable: %s", vault.Profile, strings.Join(profiles, ", "))}}}, nil
		}

		if args.Action == "set" {
			p := GetProfile(args.Profile)
			if p.Name == "" {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Invalid profile name"}}}, nil
			}
			vault.Profile = args.Profile
			vault.CurrentProfileParams = &p
			saveVault(vault, masterPwd, vaultPath)
			LogAction("MCP_PROFILE_CHANGED", fmt.Sprintf("Changed profile to %s", args.Profile))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Profile updated"}}}, nil
		}

		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Unknown action"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "manage_spaces",
		Description: "List, create or switch spaces",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"list", "add", "switch"}},
				"name":   map[string]any{"type": "string"},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "manage_spaces") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Action string `json:"action"`
			Name   string `json:"name"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}
		if r := mcpRefuseNewer(vault); r != nil {
			return r, nil
		}

		switch args.Action {
		case "list":
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Current Space: %s\nAll Spaces: %s", vault.CurrentSpace, strings.Join(vault.Spaces, ", "))}}}, nil
		case "add":
			for _, s := range vault.Spaces {
				if s == args.Name {
					return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Space already exists"}}}, nil
				}
			}
			vault.Spaces = append(vault.Spaces, args.Name)
			saveVault(vault, masterPwd, vaultPath)
			LogAction("MCP_SPACE_ADDED", fmt.Sprintf("Added space %s", args.Name))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Space added"}}}, nil
		case "switch":
			found := false
			for _, s := range vault.Spaces {
				if s == args.Name {
					found = true
					break
				}
			}
			if !found && args.Name != "" && args.Name != "default" {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Space not found"}}}, nil
			}
			if args.Name == "default" {
				vault.CurrentSpace = ""
			} else {
				vault.CurrentSpace = args.Name
			}
			saveVault(vault, masterPwd, vaultPath)
			LogAction("MCP_SPACE_SWITCHED", fmt.Sprintf("Switched to space %s", args.Name))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Switched to %s", args.Name)}}}, nil
		}

		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Unknown action"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "cloud_config",
		Description: "Configure cloud sync credentials",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider": map[string]any{"type": "string", "enum": []string{"gdrive", "github"}},
				"token":    map[string]any{"type": "string"},
				"repo":     map[string]any{"type": "string"},
			},
			"required": []string{"provider", "token"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "cloud_config") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Provider string `json:"provider"`
			Token    string `json:"token"`
			Repo     string `json:"repo"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}
		if r := mcpRefuseNewer(vault); r != nil {
			return r, nil
		}

		if args.Provider == "gdrive" {
			vault.CloudToken = []byte(args.Token)
		} else {
			vault.GitHubToken = args.Token
			vault.GitHubRepo = args.Repo
		}

		if err := saveVault(vault, masterPwd, vaultPath); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Save Error: %v", err)}}}, nil
		}
		LogAction("MCP_CLOUD_CONFIG", fmt.Sprintf("Updated %s config", args.Provider))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Cloud configuration updated"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "get_history",
		Description: "View vault item history (audit logs for specific items)",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit": map[string]any{"type": "integer"},
			},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "get_history") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Limit int `json:"limit"`
		}
		json.Unmarshal(req.Params.Arguments, &args)
		if args.Limit <= 0 {
			args.Limit = 20
		}

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		history := vault.History
		if len(history) > args.Limit {
			history = history[len(history)-args.Limit:]
		}

		var sb strings.Builder
		sb.WriteString("Vault History:\n")
		for i := len(history) - 1; i >= 0; i-- {
			h := history[i]
			sb.WriteString(fmt.Sprintf("[%s] %s %s: %s\n", h.Timestamp.Format(time.RFC3339), h.Action, h.Category, h.Identifier))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "generate_password",
		Description: "Generate a secure random password",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"length": map[string]any{"type": "integer", "minimum": 1, "maximum": mcpMaxPasswordLength}}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "generate_password") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Length int `json:"length"`
		}
		json.Unmarshal(req.Params.Arguments, &args)
		if args.Length == 0 {
			args.Length = 20
		}
		if args.Length < 1 || args.Length > mcpMaxPasswordLength {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("length must be between 1 and %d", mcpMaxPasswordLength)}}}, nil
		}
		pwd, err := GeneratePassword(args.Length)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Could not generate a password"}}}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: pwd}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "cloud_sync",
		Description: "Trigger cloud sync",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"provider": map[string]any{"type": "string", "enum": []string{"gdrive", "github"}}}, "required": []string{"provider"}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "cloud_sync") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Provider string `json:"provider"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}
		if r := mcpRefuseNewer(vault); r != nil {
			return r, nil
		}
		cm, err := GetCloudProvider(args.Provider, context.Background(), vault.CloudCredentials, vault.CloudToken, "apm_public")
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Cloud Init Error"}}}, nil
		}

		targetID := vault.CloudFileID
		if args.Provider == "github" {
			targetID = vault.GitHubRepo
		}
		if targetID == "" {
			uploadPath, cleanupUpload, prepErr := PrepareCloudUploadVaultPath(vault, masterPwd, vaultPath, args.Provider)
			if prepErr != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Ignore parse failed: %v", prepErr)}}}, nil
			}
			defer cleanupUpload()

			newID, err := cm.UploadVault(uploadPath, vault.RetrievalKey)
			if err != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Upload failed: %v", err)}}}, nil
			}
			if args.Provider == "gdrive" {
				vault.CloudFileID = newID
			} else {
				vault.GitHubRepo = newID
			}
			saveVault(vault, masterPwd, vaultPath)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Uploaded to %s (ID: %s)", args.Provider, newID)}}}, nil
		}
		uploadPath, cleanupUpload, prepErr := PrepareCloudUploadVaultPath(vault, masterPwd, vaultPath, args.Provider)
		if prepErr != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Ignore parse failed: %v", prepErr)}}}, nil
		}
		defer cleanupUpload()

		if err := cm.SyncVault(uploadPath, targetID); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Sync failed: %v", err)}}}, nil
		}
		LogAction("MCP_CLOUD_SYNC", fmt.Sprintf("Synced to %s", args.Provider))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Sync successful"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "get_audit_logs",
		Description: "Retrieve recent audit logs",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer"}}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "get_audit_logs") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Limit int `json:"limit"`
		}
		json.Unmarshal(req.Params.Arguments, &args)
		if args.Limit == 0 {
			args.Limit = 50
		}
		logs, _ := GetAuditLogs(args.Limit)
		var sb strings.Builder
		for _, l := range logs {
			sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", l.Timestamp.Format(time.RFC3339), l.Action, l.Details))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "tx_list",
		Description: "List pending/recent MCP mutation transactions",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer"}}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "tx_list") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(req.Params.Arguments, &args)
		if args.Limit == 0 {
			args.Limit = 25
		}
		txs, err := ListMCPTransactions(args.Limit)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}}}, nil
		}
		if len(txs) == 0 {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "No active transactions"}}}, nil
		}
		var sb strings.Builder
		for _, tx := range txs {
			sb.WriteString(fmt.Sprintf("%s | %s | %s | %s | expires=%s\n", tx.ID, tx.Tool, tx.TokenName, tx.Status, tx.ExpiresAt.Format(time.RFC3339)))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "tx_abort",
		Description: "Abort a pending MCP transaction by id",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"tx_id": map[string]any{"type": "string"}}, "required": []string{"tx_id"}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "tx_abort") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			TxID string `json:"tx_id"`
		}
		_ = json.Unmarshal(req.Params.Arguments, &args)
		if err := AbortMCPTransaction(args.TxID); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}}}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Transaction aborted"}}}, nil
	})

	if transport == nil {
		transport = &mcp.StdioTransport{}
	}
	return s.Run(context.Background(), transport)
}

// mcpRefuseNewer stops an MCP write against a vault from a newer pm.
func mcpRefuseNewer(v *Vault) *mcp.CallToolResult {
	if !v.IsNewerFormat() {
		return nil
	}
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error: " + ErrVaultNewer.Error()}}}
}

func saveVault(vault *Vault, masterPwd string, path string) error {
	data, err := EncryptVault(vault, masterPwd)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func encryptEpisodic(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(plaintext) < nonceSize {
		return nil, fmt.Errorf("plaintext too short")
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptEpisodic(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func writeToTemp(data []byte) (string, error) {
	tempFile, err := os.CreateTemp("", "apm_mcp_*.enc")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()
	if _, err := tempFile.Write(data); err != nil {
		return "", err
	}
	return tempFile.Name(), nil
}

func hasPermission(scopes []string, required string) bool {
	if required == "" {
		return false
	}

	required = strings.TrimSpace(required)
	for _, s := range scopes {
		scope := strings.TrimSpace(s)
		if scope == required || scope == "all" {
			return true
		}
	}

	for _, s := range scopes {
		for _, allowed := range legacyMCPScopePermissions[strings.TrimSpace(s)] {
			if allowed == required {
				return true
			}
		}
	}

	return false
}

func unlockVaultForMCP(vaultPath string) (*Vault, string, error) {
	session, err := GetSession()
	if err != nil {
		ephID := strings.TrimSpace(os.Getenv("APM_EPHEMERAL_ID"))
		if ephID == "" {
			return nil, "", errors.New("vault is locked. please run 'pm unlock' first to start an MCP session")
		}
		eph, ephErr := ValidateEphemeralSession(ephID, os.Getpid(), strings.TrimSpace(os.Getenv("APM_EPHEMERAL_AGENT")))
		if ephErr != nil {
			return nil, "", errors.New("vault is locked and ephemeral session is invalid")
		}
		data, loadErr := LoadVault(vaultPath)
		if loadErr != nil {
			return nil, "", loadErr
		}
		vault, decErr := DecryptVault(data, eph.MasterPassword, 1)
		if decErr != nil {
			return nil, "", decErr
		}
		return vault, eph.MasterPassword, nil
	}

	data, err := LoadVault(vaultPath)
	if err != nil {
		fmt.Printf("DEBUG: LoadVault error: %v\n", err)
		return nil, "", err
	}

	if session.ReadOnly {
		return GetDecoyVault(), session.MasterPassword, nil
	}

	vault, err := DecryptVault(data, session.MasterPassword, 1)
	if err != nil {
		fmt.Printf("DEBUG: DecryptVault error: %v\n", err)
		return nil, "", err
	}

	return vault, session.MasterPassword, nil
}
