package apm

import (
	"encoding/json"
	"fmt"
	"time"
)

type MCPAddEntryArgs struct {
	Type          string   `json:"type"`
	Name          string   `json:"name"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Secret        string   `json:"secret"`
	Content       string   `json:"content"`
	Space         string   `json:"space"`
	Service       string   `json:"service"`
	Key           string   `json:"key"`
	TokenVal      string   `json:"token_val"`
	TokenType     string   `json:"token_type"`
	SSID          string   `json:"ssid"`
	Security      string   `json:"security"`
	RouterIP      string   `json:"router_ip"`
	Codes         []string `json:"codes"`
	Issuer        string   `json:"issuer"`
	Expiry        string   `json:"expiry"`
	Label         string   `json:"label"`
	BankType      string   `json:"bank_type"`
	Details       string   `json:"details"`
	CVV           string   `json:"cvv"`
	IDNumber      string   `json:"id_number"`
	IDType        string   `json:"id_type"`
	FullName      string   `json:"full_name"`
	InsuranceID   string   `json:"insurance_id"`
	Prescriptions string   `json:"prescriptions"`
	Allergies     string   `json:"allergies"`
	TicketNumber  string   `json:"ticket_number"`
	BookingCode   string   `json:"booking_code"`
	Loyalty       string   `json:"loyalty"`
	Phone         string   `json:"phone"`
	Email         string   `json:"email"`
	Address       string   `json:"address"`
	Emergency     bool     `json:"emergency"`
	AccessKey     string   `json:"access_key"`
	SecretKey     string   `json:"secret_key"`
	Region        string   `json:"region"`
	AccountID     string   `json:"account_id"`
	Role          string   `json:"role"`
	ClusterURL    string   `json:"cluster_url"`
	Namespace     string   `json:"namespace"`
	RegistryURL   string   `json:"registry_url"`
	Alias         string   `json:"alias"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	KeyPath       string   `json:"key_path"`
	Fingerprint   string   `json:"fingerprint"`
	Webhook       string   `json:"webhook"`
	EnvVars       string   `json:"env_vars"`
	ProductName   string   `json:"product_name"`
	SerialKey     string   `json:"serial_key"`
	Activation    string   `json:"activation"`
	Summary       string   `json:"summary"`
	Parties       string   `json:"parties"`
	SignedDate    string   `json:"signed_date"`
	FileName      string   `json:"file_name"`
	Tags          []string `json:"tags"`
}

func ApplyMCPAddEntry(vault *Vault, args MCPAddEntryArgs) error {
	if args.Space == "default" {
		args.Space = ""
	}
	vault.CurrentSpace = args.Space

	var opErr error
	switch args.Type {
	case "password":
		opErr = vault.AddEntry(args.Name, args.Username, args.Password)
	case "totp":
		opErr = vault.AddTOTPEntry(args.Name, args.Secret)
	case "note":
		opErr = vault.AddSecureNote(args.Name, args.Content)
	case "token":
		opErr = vault.AddToken(args.Name, args.TokenVal, args.TokenType)
	case "api_key":
		opErr = vault.AddAPIKey(args.Name, args.Service, args.Key)
	case "ssh_key":
		opErr = vault.AddSSHKey(args.Name, args.Content)
	case "wifi":
		opErr = vault.AddWiFi(args.SSID, args.Password, args.Security)
		if opErr == nil && args.RouterIP != "" {
			for i, w := range vault.WiFiCredentials {
				if w.SSID == args.SSID {
					vault.WiFiCredentials[i].RouterIP = args.RouterIP
				}
			}
		}
	case "recovery_code":
		opErr = vault.AddRecoveryCode(args.Service, args.Codes)
	case "certificate":
		exp, _ := time.Parse("2006-01-02", args.Expiry)
		opErr = vault.AddCertificate(args.Label, args.Content, args.Key, args.Issuer, exp)
	case "banking":
		opErr = vault.AddBankingItem(args.Label, args.BankType, args.Details, args.CVV, args.Expiry)
	case "gov_id":
		opErr = vault.AddGovID(GovIDEntry{Type: args.IDType, IDNumber: args.IDNumber, Name: args.FullName, Expiry: args.Expiry})
	case "medical":
		opErr = vault.AddMedicalRecord(MedicalRecordEntry{Label: args.Label, InsuranceID: args.InsuranceID, Prescriptions: args.Prescriptions, Allergies: args.Allergies})
	case "travel":
		opErr = vault.AddTravelDoc(TravelEntry{Label: args.Label, TicketNumber: args.TicketNumber, BookingCode: args.BookingCode, LoyaltyProgram: args.Loyalty})
	case "contact":
		opErr = vault.AddContact(ContactEntry{Name: args.Name, Phone: args.Phone, Email: args.Email, Address: args.Address, Emergency: args.Emergency})
	case "cloud":
		opErr = vault.AddCloudCredential(CloudCredentialEntry{Label: args.Label, AccessKey: args.AccessKey, SecretKey: args.SecretKey, Region: args.Region, AccountID: args.AccountID, Role: args.Role, Expiration: args.Expiry})
	case "k8s_secret":
		opErr = vault.AddK8sSecret(K8sSecretEntry{Name: args.Name, ClusterURL: args.ClusterURL, K8sNamespace: args.Namespace, Expiration: args.Expiry})
	case "docker":
		opErr = vault.AddDockerRegistry(DockerRegistryEntry{Name: args.Name, RegistryURL: args.RegistryURL, Username: args.Username, Token: args.TokenVal})
	case "ssh_config":
		opErr = vault.AddSSHConfig(SSHConfigEntry{Alias: args.Alias, Host: args.Host, User: args.Username, Port: args.Port, KeyPath: args.KeyPath, PrivateKey: args.Content, Fingerprint: args.Fingerprint})
	case "cicd":
		opErr = vault.AddCICDSecret(CICDSecretEntry{Name: args.Name, Webhook: args.Webhook, EnvVars: args.EnvVars})
	case "license":
		opErr = vault.AddSoftwareLicense(SoftwareLicenseEntry{ProductName: args.ProductName, SerialKey: args.SerialKey, ActivationInfo: args.Activation, Expiration: args.Expiry})
	case "contract":
		opErr = vault.AddLegalContract(LegalContractEntry{Name: args.Name, Summary: args.Summary, PartiesInvolved: args.Parties, SignedDate: args.SignedDate})
	case "document":
		opErr = vault.AddDocument(args.Name, args.FileName, []byte(args.Content), args.Password, args.Tags, args.Expiry)
	case "audio":
		opErr = vault.AddAudio(args.Name, args.FileName, []byte(args.Content))
	case "video":
		opErr = vault.AddVideo(args.Name, args.FileName, []byte(args.Content))
	case "photo":
		opErr = vault.AddPhoto(args.Name, args.FileName, []byte(args.Content))
	default:
		opErr = fmt.Errorf("unsupported entry type %q", args.Type)
	}
	return opErr
}

type MCPEditEntryArgs struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	Secret   string `json:"secret"`
	Content  string `json:"content"`
	Space    string `json:"space"`
}

func ApplyMCPEditEntry(vault *Vault, args MCPEditEntryArgs) bool {
	if args.Space == "default" {
		args.Space = ""
	}
	vault.CurrentSpace = args.Space

	switch args.Type {
	case "password":
		for i, e := range vault.Entries {
			if e.Account == args.Name && e.Space == vault.CurrentSpace {
				if args.Username != "" {
					vault.Entries[i].Username = args.Username
				}
				if args.Password != "" {
					vault.Entries[i].Password = args.Password
				}
				return true
			}
		}
	case "totp":
		for i, e := range vault.TOTPEntries {
			if e.Account == args.Name && e.Space == vault.CurrentSpace {
				if args.Secret != "" {
					vault.TOTPEntries[i].Secret = args.Secret
				}
				return true
			}
		}
	case "note":
		for i, e := range vault.SecureNotes {
			if e.Name == args.Name && e.Space == vault.CurrentSpace {
				if args.Content != "" {
					vault.SecureNotes[i].Content = args.Content
				}
				return true
			}
		}
	}
	return false
}

func ApplyMCPDeleteEntry(vault *Vault, name string) bool {
	return vault.DeleteEntry(name) || vault.DeleteTOTPEntry(name) || vault.DeleteSecureNote(name)
}

func ApplyMCPTransaction(vault *Vault, tool string, raw json.RawMessage) (string, error) {
	switch tool {
	case "add_entry":
		var args MCPAddEntryArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		if err := ApplyMCPAddEntry(vault, args); err != nil {
			return "", err
		}
		return "added:" + args.Name, nil
	case "edit_entry":
		var args MCPEditEntryArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		if !ApplyMCPEditEntry(vault, args) {
			return "", fmt.Errorf("entry not found or editing not supported for this type")
		}
		return "edited:" + args.Name, nil
	case "delete_entry":
		var args struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", err
		}
		if !ApplyMCPDeleteEntry(vault, args.Name) {
			return "", fmt.Errorf("entry not found")
		}
		return "deleted:" + args.Name, nil
	}
	return "", fmt.Errorf("unsupported transaction tool: %s", tool)
}
