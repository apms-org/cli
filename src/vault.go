package apm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const VaultHeader = "APMVAULT"

const CurrentVersion = 4

func GetVaultParams(data []byte) (CryptoProfile, int, error) {
	if len(data) < len(VaultHeader) || string(data[:len(VaultHeader)]) != VaultHeader {
		return CryptoProfile{}, 0, errors.New("invalid vault header")
	}
	offset := len(VaultHeader)
	version := data[offset]
	offset++

	switch version {
	case 1:
		return ProfileStandard, 1, nil
	case 2:
		if offset >= len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		nameLen := int(data[offset])
		offset++
		if offset+nameLen > len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		name := string(data[offset : offset+nameLen])
		return GetProfile(name), 2, nil
	case 3, 4:
		if offset+2 > len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		pLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		if offset+pLen > len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		pBytes := data[offset : offset+pLen]
		var p CryptoProfile
		if err := json.Unmarshal(pBytes, &p); err != nil {
			return CryptoProfile{}, 0, err
		}
		return NormalizeCryptoProfile(p), int(version), nil
	default:
		return CryptoProfile{}, 0, fmt.Errorf("unsupported version: %d", version)
	}
}

func newAEAD(key []byte, profile CryptoProfile) (cipher.AEAD, error) {
	profile = NormalizeCryptoProfile(profile)
	switch profile.Cipher {
	case CipherAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCMWithNonceSize(block, profile.NonceLen)
	case CipherXChaCha20Poly1305:
		if profile.NonceLen != chacha20poly1305.NonceSizeX {
			return nil, fmt.Errorf("xchacha20-poly1305 requires a %d-byte nonce", chacha20poly1305.NonceSizeX)
		}
		return chacha20poly1305.NewX(key)
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", profile.Cipher)
	}
}

type Entry struct {
	Account  string        `json:"account"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	URLs     []string      `json:"urls,omitempty"`
	Website  string        `json:"website,omitempty"`
	Space    string        `json:"space,omitempty"`
	Passkeys []Passkey     `json:"passkeys,omitempty"`
	Notes    string        `json:"notes,omitempty"`
	TOTP     string        `json:"totp,omitempty"`
	Fields   []CustomField `json:"fields,omitempty"`
}

// CustomField is a free-form label/value pair on a login, such as a PIN or a
// security answer. Hidden values are masked and treated as secrets.
type CustomField struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Hidden bool   `json:"hidden,omitempty"`
}

type TOTPEntry struct {
	Account string `json:"account"`
	Secret  string `json:"secret"`
	Space   string `json:"space,omitempty"`
}

type TokenEntry struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Type  string `json:"type"`
	Space string `json:"space,omitempty"`
}

type SecureNoteEntry struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Space   string `json:"space,omitempty"`
}

type APIKeyEntry struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	Key     string `json:"key"`
	Space   string `json:"space,omitempty"`
}

type SSHKeyEntry struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Space      string `json:"space,omitempty"`
}

type WiFiEntry struct {
	SSID         string `json:"ssid"`
	Password     string `json:"password"`
	SecurityType string `json:"security_type"`
	RouterIP     string `json:"router_ip"`
	Space        string `json:"space,omitempty"`
}

type GovIDEntry struct {
	Type     string `json:"type"`
	IDNumber string `json:"id_number"`
	Name     string `json:"name"`
	Expiry   string `json:"expiry"`
	Space    string `json:"space,omitempty"`
}

type MedicalRecordEntry struct {
	Label         string `json:"label"`
	InsuranceID   string `json:"insurance_id"`
	Prescriptions string `json:"prescriptions"`
	Allergies     string `json:"allergies"`
	Space         string `json:"space,omitempty"`
}

type TravelEntry struct {
	Label          string `json:"label"`
	TicketNumber   string `json:"ticket_number"`
	BookingCode    string `json:"booking_code"`
	LoyaltyProgram string `json:"loyalty_program"`
	Space          string `json:"Space,omitempty"`
}

type ContactEntry struct {
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	Email     string `json:"email"`
	Address   string `json:"address"`
	Emergency bool   `json:"emergency"`
	Space     string `json:"space,omitempty"`
}

type CloudCredentialEntry struct {
	Label      string `json:"label"`
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	Region     string `json:"region"`
	AccountID  string `json:"account_id"`
	Role       string `json:"role"`
	Expiration string `json:"expiration"`
	Space      string `json:"space,omitempty"`
}

type K8sSecretEntry struct {
	Name         string `json:"name"`
	ClusterURL   string `json:"cluster_url"`
	K8sNamespace string `json:"namespace"`
	Expiration   string `json:"expiration"`
	Space        string `json:"space,omitempty"`
}

type DockerRegistryEntry struct {
	Name        string `json:"name"`
	RegistryURL string `json:"registry_url"`
	Username    string `json:"username"`
	Token       string `json:"token"`
	Space       string `json:"Space,omitempty"`
}

type SSHConfigEntry struct {
	Alias       string `json:"alias"`
	Host        string `json:"host"`
	User        string `json:"user"`
	Port        string `json:"port"`
	KeyPath     string `json:"key_path"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
	Space       string `json:"Space,omitempty"`
}

type CICDSecretEntry struct {
	Name    string `json:"name"`
	Webhook string `json:"webhook"`
	EnvVars string `json:"env_vars"`
	Space   string `json:"space,omitempty"`
}

type SoftwareLicenseEntry struct {
	ProductName    string `json:"product_name"`
	SerialKey      string `json:"serial_key"`
	ActivationInfo string `json:"activation_info"`
	Expiration     string `json:"expiration"`
	Space          string `json:"Space,omitempty"`
}

type LegalContractEntry struct {
	Name            string `json:"name"`
	Summary         string `json:"summary"`
	PartiesInvolved string `json:"parties_involved"`
	SignedDate      string `json:"signed_date"`
	Space           string `json:"space,omitempty"`
}

type RecoveryCodeEntry struct {
	Service string   `json:"service"`
	Codes   []string `json:"codes"`
	Used    []string `json:"used,omitempty"`
	Space   string   `json:"space,omitempty"`
}

type HistoryEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	Category   string    `json:"category"`
	Identifier string    `json:"identifier"`
	PrevHash   string    `json:"prev_hash,omitempty"`
	Hash       string    `json:"hash,omitempty"`
	Signature  string    `json:"signature,omitempty"`
}

type CertificateEntry struct {
	Label      string    `json:"label"`
	CertData   string    `json:"cert_data"`
	PrivateKey string    `json:"private_key"`
	Issuer     string    `json:"issuer"`
	Expiry     time.Time `json:"expiry"`
	Space      string    `json:"space,omitempty"`
}

type BankingEntry struct {
	Label    string `json:"label"`
	Type     string `json:"type"`
	Details  string `json:"details"`
	CVV      string `json:"cvv,omitempty"`
	Expiry   string `json:"expiry,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
	Space    string `json:"space,omitempty"`
}

type DocumentEntry struct {
	Name     string   `json:"name"`
	FileName string   `json:"file_name"`
	Content  []byte   `json:"content"`
	Password string   `json:"password"`
	Tags     []string `json:"tags,omitempty"`
	Expiry   string   `json:"expiry,omitempty"`
	Space    string   `json:"space,omitempty"`
}

type RecoveryData struct {
	EmailHash              []byte            `json:"email_hash,omitempty"`
	KeyHash                []byte            `json:"key_hash,omitempty"`
	DEKSlot                []byte            `json:"dek_slot,omitempty"` // DEK encrypted with Recovery Key
	Salt                   []byte            `json:"salt,omitempty"`     // Stable salt for recovery key
	ObfuscatedKey          []byte            `json:"obfuscated_key,omitempty"`
	RecoveryTokenHash      []byte            `json:"recovery_token_hash,omitempty"`
	RecoveryTokenExpiry    time.Time         `json:"recovery_token_expiry,omitempty"`
	RecoveryShareThreshold int               `json:"recovery_share_threshold,omitempty"`
	RecoveryShareCount     int               `json:"recovery_share_count,omitempty"`
	RecoveryShareHashes    map[string][]byte `json:"recovery_share_hashes,omitempty"`
	RecoveryCodeHashes     [][]byte          `json:"recovery_code_hashes,omitempty"`
	RecoveryCodeUsed       []bool            `json:"recovery_code_used,omitempty"`
	RecoveryPasskeyEnabled bool              `json:"recovery_passkey_enabled,omitempty"`
	RecoveryPasskeyUserID  []byte            `json:"recovery_passkey_user_id,omitempty"`
	RecoveryPasskeyCred    []byte            `json:"recovery_passkey_cred,omitempty"`
	AlertsEnabled          bool              `json:"alerts_enabled,omitempty"`
	SecurityLevel          int               `json:"security_level,omitempty"`
	AlertEmail             string            `json:"alert_email,omitempty"`
	EmailHint              string            `json:"email_hint,omitempty"`
}

type AudioEntry struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Space    string `json:"space,omitempty"`
}

type VideoEntry struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Space    string `json:"space,omitempty"`
}

type PhotoEntry struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Space    string `json:"space,omitempty"`
}

type Vault struct {
	Salt                       []byte                 `json:"salt"`
	SecurityLevel              int                    `json:"security_level"` // 1-3
	Entries                    []Entry                `json:"entries"`
	TOTPEntries                []TOTPEntry            `json:"totp_entries"`
	TOTPOrder                  []string               `json:"totp_order,omitempty"`
	TOTPDomainLinks            map[string]string      `json:"totp_domain_links,omitempty"`
	Tokens                     []TokenEntry           `json:"tokens"`
	SecureNotes                []SecureNoteEntry      `json:"secure_notes"`
	APIKeys                    []APIKeyEntry          `json:"api_keys"`
	SSHKeys                    []SSHKeyEntry          `json:"ssh_keys"`
	WiFiCredentials            []WiFiEntry            `json:"wifi_credentials"`
	RecoveryCodeItems          []RecoveryCodeEntry    `json:"recovery_codes"`
	Certificates               []CertificateEntry     `json:"certificates"`
	BankingItems               []BankingEntry         `json:"banking_items"`
	Documents                  []DocumentEntry        `json:"documents"`
	AudioFiles                 []AudioEntry           `json:"audio_files"`
	VideoFiles                 []VideoEntry           `json:"video_files"`
	PhotoFiles                 []PhotoEntry           `json:"photo_files"`
	GovIDs                     []GovIDEntry           `json:"gov_ids"`
	MedicalRecords             []MedicalRecordEntry   `json:"medical_records"`
	TravelDocs                 []TravelEntry          `json:"travel_docs"`
	Contacts                   []ContactEntry         `json:"contacts"`
	CloudCredentialsItems      []CloudCredentialEntry `json:"cloud_credentials_items"`
	K8sSecrets                 []K8sSecretEntry       `json:"k8s_secrets"`
	DockerRegistries           []DockerRegistryEntry  `json:"docker_registries"`
	SSHConfigs                 []SSHConfigEntry       `json:"ssh_configs"`
	CICDSecrets                []CICDSecretEntry      `json:"cicd_secrets"`
	SoftwareLicenses           []SoftwareLicenseEntry `json:"software_licenses"`
	LegalContracts             []LegalContractEntry   `json:"legal_contracts"`
	History                    []HistoryEntry         `json:"history"`
	RetrievalKey               string                 `json:"retrieval_key,omitempty"`
	CloudFileID                string                 `json:"cloud_file_id,omitempty"`
	CloudCredentials           []byte                 `json:"cloud_credentials,omitempty"`
	CloudToken                 []byte                 `json:"cloud_token,omitempty"`
	FailedAttempts             uint8                  `json:"failed_attempts,omitempty"`
	EmergencyMode              bool                   `json:"emergency_mode,omitempty"`
	DecoyMode                  bool                   `json:"decoy_mode,omitempty"`
	DecoySessionCount          int                    `json:"decoy_session_count,omitempty"`
	Profile                    string                 `json:"profile,omitempty"`
	AutocompleteWindowDisabled bool                   `json:"autocomplete_window_disabled,omitempty"`

	AlertEmail                string   `json:"alert_email,omitempty"`
	AlertsEnabled             bool     `json:"alerts_enabled,omitempty"`
	AnomalyDetectionEnabled   bool     `json:"anomaly_detection_enabled,omitempty"`
	LastCloudProvider         string   `json:"last_cloud_provider,omitempty"`
	DriveSyncMode             string   `json:"drive_sync_mode,omitempty"` // "apm_public" or "self_hosted"
	DriveKeyMetadataConsent   bool     `json:"drive_key_metadata_consent,omitempty"`
	GitHubToken               string   `json:"github_token,omitempty"`
	GitHubRepo                string   `json:"github_repo,omitempty"`
	DropboxToken              []byte   `json:"dropbox_token,omitempty"`
	DropboxSyncMode           string   `json:"dropbox_sync_mode,omitempty"`
	DropboxKeyMetadataConsent bool     `json:"dropbox_key_metadata_consent,omitempty"`
	DropboxFileID             string   `json:"dropbox_file_id,omitempty"`
	CurrentSpace              string   `json:"current_space,omitempty"`
	Spaces                    []string `json:"spaces"`
	ActivePolicy              Policy   `json:"active_policy,omitempty"`
	NeedsRepair               bool     `json:"-"`

	CurrentProfileParams   *CryptoProfile             `json:"-"`
	AuthKey                []byte                     `json:"-"` // derived auth key for HMAC signing (never serialized)
	RecoveryEmail          string                     `json:"recovery_email,omitempty"`
	RecoveryHash           []byte                     `json:"recovery_hash,omitempty"`
	DEK                    []byte                     `json:"dek,omitempty"`
	RecoverySlot           []byte                     `json:"recovery_slot,omitempty"`
	RecoverySalt           []byte                     `json:"recovery_salt,omitempty"`
	RawRecoveryKey         string                     `json:"-"`
	ObfuscatedKey          []byte                     `json:"-"`
	RecoveryTokenHash      []byte                     `json:"recovery_token_hash,omitempty"`
	RecoveryTokenExpiry    time.Time                  `json:"recovery_token_expiry,omitempty"`
	RecoveryShareThreshold int                        `json:"recovery_share_threshold,omitempty"`
	RecoveryShareCount     int                        `json:"recovery_share_count,omitempty"`
	RecoveryShareHashes    map[string][]byte          `json:"recovery_share_hashes,omitempty"`
	SecretTelemetry        map[string]SecretTelemetry `json:"secret_telemetry,omitempty"`
	RecoveryCodeHashes     [][]byte                   `json:"recovery_code_hashes,omitempty"`
	RecoveryCodeUsed       []bool                     `json:"recovery_code_used,omitempty"`
	RecoveryPasskeyEnabled bool                       `json:"recovery_passkey_enabled,omitempty"`
	RecoveryPasskeyUserID  []byte                     `json:"recovery_passkey_user_id,omitempty"`
	RecoveryPasskeyCred    []byte                     `json:"recovery_passkey_cred,omitempty"`
	Desktop                *DesktopState              `json:"desktop,omitempty"`
}

func (v *Vault) Serialize(masterPassword string) ([]byte, error) {
	return EncryptVault(v, masterPassword)
}

// EncryptVault writes the current vault format with a DEK-wrapped payload. The
// master password protects the DEK slot and integrity metadata, while the DEK
// itself encrypts the JSON body so future password changes do not require
// re-encrypting individual vault items.
func EncryptVault(vault *Vault, masterPassword string) ([]byte, error) {
	var profile CryptoProfile
	if vault.CurrentProfileParams != nil {
		profile = *vault.CurrentProfileParams
		if profile.Name == "" {
			profile.Name = "custom"
		}
	} else {
		if vault.Profile == "" {
			vault.Profile = "standard"
		}
		profile = GetProfile(vault.Profile)
	}
	profile = NormalizeCryptoProfile(profile)
	vault.CurrentProfileParams = &profile

	salt, err := GenerateSalt(profile.SaltLen)
	if err != nil {
		return nil, err
	}

	keys := DeriveKeys(masterPassword, salt, profile.Time, profile.Memory, profile.Parallelism)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)
	defer Wipe(keys.Validator)

	if len(vault.DEK) == 0 {
		vault.DEK = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, vault.DEK); err != nil {
			return nil, err
		}
	}

	jsonData, err := json.Marshal(vault)
	if err != nil {
		return nil, err
	}

	dekAEAD, err := newAEAD(vault.DEK, profile)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, dekAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := dekAEAD.Seal(nil, nonce, jsonData, nil)

	var payload []byte
	payload = append(payload, []byte(VaultHeader)...)
	payload = append(payload, byte(CurrentVersion))

	encProfile, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	lenBytes := make([]byte, 2)
	lenBytes[0] = byte(len(encProfile) >> 8)
	lenBytes[1] = byte(len(encProfile))
	payload = append(payload, lenBytes...)
	payload = append(payload, encProfile...)

	// V4 keeps recovery metadata outside the encrypted payload so recovery
	// checks can inspect state without first opening the vault body.
	var rec RecoveryData
	if vault.RecoveryEmail != "" {
		h := sha256.Sum256([]byte(strings.ToLower(vault.RecoveryEmail)))
		rec.EmailHash = h[:]
		rec.EmailHint = MaskEmailHint(vault.RecoveryEmail)
	}

	if len(vault.RecoverySlot) > 0 {
		rec.DEKSlot = vault.RecoverySlot
		rec.KeyHash = vault.RecoveryHash
		rec.Salt = vault.RecoverySalt
	}

	if vault.RawRecoveryKey != "" {
		rec.ObfuscatedKey = XORRecoveryKey(vault.RawRecoveryKey)
	} else if len(vault.ObfuscatedKey) > 0 {
		rec.ObfuscatedKey = vault.ObfuscatedKey
	}

	if len(vault.RecoveryTokenHash) > 0 {
		rec.RecoveryTokenHash = vault.RecoveryTokenHash
		rec.RecoveryTokenExpiry = vault.RecoveryTokenExpiry
	}
	if vault.RecoveryShareThreshold > 0 && len(vault.RecoveryShareHashes) > 0 {
		rec.RecoveryShareThreshold = vault.RecoveryShareThreshold
		rec.RecoveryShareCount = vault.RecoveryShareCount
		rec.RecoveryShareHashes = vault.RecoveryShareHashes
	}
	if len(vault.RecoveryCodeHashes) > 0 {
		rec.RecoveryCodeHashes = vault.RecoveryCodeHashes
		rec.RecoveryCodeUsed = vault.RecoveryCodeUsed
	}
	if vault.RecoveryPasskeyEnabled && len(vault.RecoveryPasskeyUserID) > 0 && len(vault.RecoveryPasskeyCred) > 0 {
		rec.RecoveryPasskeyEnabled = true
		rec.RecoveryPasskeyUserID = vault.RecoveryPasskeyUserID
		rec.RecoveryPasskeyCred = vault.RecoveryPasskeyCred
	}

	rec.AlertsEnabled = vault.AlertsEnabled
	rec.SecurityLevel = vault.SecurityLevel
	rec.AlertEmail = vault.AlertEmail

	encRec, _ := json.Marshal(rec)
	recLenBytes := make([]byte, 2)
	recLenBytes[0] = byte(len(encRec) >> 8)
	recLenBytes[1] = byte(len(encRec))
	payload = append(payload, recLenBytes...)
	payload = append(payload, encRec...)

	payload = append(payload, salt...)
	payload = append(payload, keys.Validator...)
	payload = append(payload, nonce...)

	masterSlotAEAD, err := newAEAD(keys.EncryptionKey, profile)
	if err != nil {
		return nil, err
	}
	// Derive master slot nonce from salt -- each vault save generates a new
	// salt, so this nonce is unique per save without requiring storage space
	// or breaking backward compatibility.
	saltHash := sha256.Sum256(salt)
	mNonce := saltHash[:masterSlotAEAD.NonceSize()]
	masterSlot := masterSlotAEAD.Seal(nil, mNonce, vault.DEK, nil)
	payload = append(payload, masterSlot...)

	payload = append(payload, ciphertext...)

	signature := CalculateHMAC(payload, keys.AuthKey)
	finalData := append(payload, signature...)

	return finalData, nil
}

// DecryptVault dispatches between the current header-based format and the
// pre-header legacy layout that stored salt and ciphertext directly.
func DecryptVault(data []byte, masterPassword string, costMultiplier int) (*Vault, error) {
	var v *Vault
	var err error
	if len(data) > len(VaultHeader) && string(data[:len(VaultHeader)]) == VaultHeader {
		v, err = decryptNewVault(data, masterPassword, costMultiplier)
	} else {
		if len(data) < 16 {
			return nil, errors.New("invalid vault data")
		}
		v, err = decryptOldVault(data[16:], masterPassword, data[:16])
	}
	if err == nil && v.MergeLinkedTOTP() > 0 {
		v.NeedsRepair = true
	}
	return v, err
}

// decryptNewVault is intentionally tolerant of partially shifted offsets. Older
// experimental builds wrote V4 metadata in slightly different positions, so the
// parser probes for the DEK slot and ciphertext when the canonical offsets fail.
func decryptNewVault(data []byte, masterPassword string, costMultiplier int) (*Vault, error) {
	offset := len(VaultHeader)
	version := data[offset]
	offset++

	var profile CryptoProfile

	switch version {
	case 1:
		profile = NormalizeCryptoProfile(CryptoProfile{
			Name: "legacy_v1", KDF: "argon2id", Time: 3, Memory: 128 * 1024, Parallelism: 4, SaltLen: 16, NonceLen: 12,
		})
	case 2:
		if offset >= len(data) {
			return nil, errors.New("corrupted header")
		}
		nameLen := int(data[offset])
		offset++
		if offset+nameLen > len(data) {
			return nil, errors.New("corrupted header (profile name)")
		}
		profileName := string(data[offset : offset+nameLen])
		offset += nameLen
		profile = GetProfile(profileName)
	case 3, 4:
		if offset+2 > len(data) {
			return nil, errors.New("corrupted header (params len)")
		}
		pLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+pLen > len(data) {
			return nil, errors.New("corrupted header (params)")
		}
		pBytes := data[offset : offset+pLen]
		offset += pLen

		if err := json.Unmarshal(pBytes, &profile); err != nil {
			return nil, fmt.Errorf("corrupted profile data: %v", err)
		}
		profile = NormalizeCryptoProfile(profile)

		if version == 4 {
			if offset+2 > len(data) {
				return nil, errors.New("corrupted header (recovery len)")
			}
			rLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			if offset+rLen <= len(data) {
				var rec RecoveryData
				if err := json.Unmarshal(data[offset:offset+rLen], &rec); err == nil {

				}
			}
			offset += rLen
		}
	default:
		return nil, fmt.Errorf("unsupported vault version: %d", version)
	}

	if costMultiplier > 1 {
		profile.Time *= uint32(costMultiplier)
		profile.Memory *= uint32(costMultiplier)
	}

	if offset+profile.SaltLen > len(data) {
		return nil, errors.New("corrupted header (salt)")
	}
	salt := data[offset : offset+profile.SaltLen]
	offset += profile.SaltLen

	if offset+32 > len(data) {
		return nil, errors.New("corrupted header (validator)")
	}
	storedValidator := data[offset : offset+32]
	offset += 32

	if offset+profile.NonceLen > len(data) {
		return nil, errors.New("corrupted header (nonce)")
	}
	nonce := data[offset : offset+profile.NonceLen]
	offset += profile.NonceLen

	keys := DeriveKeys(masterPassword, salt, profile.Time, profile.Memory, profile.Parallelism)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)
	defer Wipe(keys.Validator)

	if !VerifyPasswordValidator(keys.Validator, storedValidator) {
		return nil, errors.New("incorrect password")
	}

	payloadForHMAC := data[:len(data)-32]
	storedHMAC := data[len(data)-32:]
	if !VerifyHMAC(payloadForHMAC, storedHMAC, keys.AuthKey) {
		return nil, errors.New("vault file has been tampered with or corrupted")
	}

	var needsRepair bool
	var dek []byte
	if version == 4 {

		slotAEAD, err := newAEAD(keys.EncryptionKey, profile)
		if err != nil {
			return nil, err
		}
		masterSlotLen := 32 + slotAEAD.Overhead()
		if offset+masterSlotLen <= len(data)-32 {
			masterSlot := data[offset : offset+masterSlotLen]
			// Derive nonce from salt (same derivation as EncryptVault) so we
			// don't need to store it separately. Backward compatible with
			// vaults that used a zero nonce pre-fix.
			saltHash := sha256.Sum256(salt)
			mNonce := saltHash[:slotAEAD.NonceSize()]
			dek, err = slotAEAD.Open(nil, mNonce, masterSlot, nil)
			if err == nil {
				offset += masterSlotLen
			} else {
				// Search nearby for legacy/shifted master slot placement before
				// falling back to the password-derived key path.
				found := false
				searchStart := offset - 128
				if searchStart < len(VaultHeader)+1 {
					searchStart = len(VaultHeader) + 1
				}
				for i := searchStart; i < offset+256; i++ {
					if i+masterSlotLen > len(data)-32 {
						break
					}
					// Try with salt-derived nonce first (new format), fall back to
					// zero nonce for vaults created before the nonce fix.
					trialSlot := data[i : i+masterSlotLen]
					dek, err = slotAEAD.Open(nil, mNonce, trialSlot, nil)
					if err != nil {
						// Legacy: vault created with zero master-slot nonce
						legacyNonce := make([]byte, slotAEAD.NonceSize())
						dek, err = slotAEAD.Open(nil, legacyNonce, trialSlot, nil)
					}
					if err == nil {
						offset = i + masterSlotLen
						found = true
						needsRepair = true
						break
					}
				}
				if !found {
					// Older vaults may not have a wrapped DEK at all, in which case
					// the password-derived key still decrypts the payload directly.
					dek = keys.EncryptionKey

				}
			}
		} else {

			dek = keys.EncryptionKey
		}
	} else {
		dek = keys.EncryptionKey
		if version < CurrentVersion {
			needsRepair = true
		}
	}

	dekAEAD, err := newAEAD(dek, profile)
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	foundCT := false

	// Probe a small window around the expected ciphertext start so vaults with
	// shifted slot metadata can still be repaired instead of failing hard.
	ctSearchStart := offset - 256
	if ctSearchStart < len(VaultHeader)+1 {
		ctSearchStart = len(VaultHeader) + 1
	}
	for i := ctSearchStart; i < offset+512; i++ {
		if i >= len(data)-32 {
			break
		}
		trialCT := data[i : len(data)-32]
		plaintext, err = dekAEAD.Open(nil, nonce, trialCT, nil)
		if err == nil {
			foundCT = true
			if i != offset {
				needsRepair = true
			}
			offset = i
			break
		}
	}

	if !foundCT {
		return nil, errors.New("failed to decrypt vault payload (incorrect password or corrupted data)")
	}

	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}

	vault.NeedsRepair = needsRepair

	if bytes.Equal(dek, keys.EncryptionKey) && version == 4 {
		vault.NeedsRepair = true
	}
	if version < CurrentVersion {
		vault.NeedsRepair = true
	}
	vault.CurrentProfileParams = &profile
	vault.AuthKey = make([]byte, len(keys.AuthKey))
	copy(vault.AuthKey, keys.AuthKey)
	if version == 4 {
		rec, _ := GetVaultRecoveryInfo(data)
		vault.AlertsEnabled = rec.AlertsEnabled
		vault.SecurityLevel = rec.SecurityLevel
		vault.AlertEmail = rec.AlertEmail
	}
	return &vault, nil
}

// DecryptVaultWithDEK is the recovery path once the caller already has a valid
// data-encryption key and only needs to locate the payload in a V4 vault blob.
func DecryptVaultWithDEK(data []byte, dek []byte) (*Vault, error) {
	offset := len(VaultHeader)
	version := data[offset]
	offset++

	if version != 4 {
		return nil, errors.New("direct DEK decryption only supported for V4")
	}

	pLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	pBytes := data[offset : offset+pLen]
	offset += pLen
	var profile CryptoProfile
	if err := json.Unmarshal(pBytes, &profile); err != nil {
		return nil, fmt.Errorf("corrupted profile in DEK decryption: %v", err)
	}
	profile = NormalizeCryptoProfile(profile)

	if offset+2 > len(data) {
		return nil, errors.New("corrupted header")
	}
	rLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + rLen

	offset += profile.SaltLen

	offset += 32

	if offset+profile.NonceLen > len(data) {
		return nil, errors.New("corrupted header (nonce)")
	}
	nonce := data[offset : offset+profile.NonceLen]
	offset += profile.NonceLen

	// Since the caller already has the DEK, this path only needs to locate the
	// payload boundaries, not validate the password-derived slot.
	var plaintext []byte
	found := false
	searchStart := offset - 128
	if searchStart < 0 {
		searchStart = 0
	}
	dekAEAD, err := newAEAD(dek, profile)
	if err != nil {
		return nil, err
	}

	for i := searchStart; i < offset+512; i++ {
		if i >= len(data)-32 {
			break
		}
		trialCT := data[i : len(data)-32]
		plaintext, err = dekAEAD.Open(nil, nonce, trialCT, nil)
		if err == nil {
			found = true
			if i != offset {

			}
			offset = i
			break
		}
	}

	if !found {
		return nil, errors.New("decryption with DEK failed: could not find valid ciphertext")
	}

	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}

	if offset != searchStart+128 {
		vault.NeedsRepair = true
	}

	if version == 4 {
		rec, _ := GetVaultRecoveryInfo(data)
		vault.ObfuscatedKey = rec.ObfuscatedKey
		vault.RecoveryTokenHash = rec.RecoveryTokenHash
		vault.RecoveryTokenExpiry = rec.RecoveryTokenExpiry
		vault.RecoveryShareThreshold = rec.RecoveryShareThreshold
		vault.RecoveryShareCount = rec.RecoveryShareCount
		vault.RecoveryShareHashes = rec.RecoveryShareHashes
		vault.RecoveryCodeHashes = rec.RecoveryCodeHashes
		vault.RecoveryCodeUsed = rec.RecoveryCodeUsed
		vault.RecoveryPasskeyEnabled = rec.RecoveryPasskeyEnabled
		vault.RecoveryPasskeyUserID = rec.RecoveryPasskeyUserID
		vault.RecoveryPasskeyCred = rec.RecoveryPasskeyCred
		vault.AlertsEnabled = rec.AlertsEnabled
		vault.SecurityLevel = rec.SecurityLevel
	}
	vault.CurrentProfileParams = &profile
	return &vault, nil
}

func UpdateMasterPassword(v *Vault, oldPass, newPass string) ([]byte, error) {
	return EncryptVault(v, newPass)
}

// GetVaultRecoveryInfo first tries the canonical V4 recovery metadata location
// and then falls back to a bounded scan so partially shifted headers remain
// recoverable instead of becoming unrecoverable parsing failures.
func GetVaultRecoveryInfo(data []byte) (RecoveryData, error) {
	if len(data) < len(VaultHeader)+1 {
		return RecoveryData{}, errors.New("invalid vault")
	}
	offset := len(VaultHeader)
	version := data[offset]
	offset++
	if version != 4 {
		return RecoveryData{}, errors.New("vault version does not support recovery")
	}

	if offset+2 <= len(data) {
		pLen := int(data[offset])<<8 | int(data[offset+1])
		rOffset := offset + 2 + pLen
		if rOffset+2 <= len(data) {
			rLen := int(data[rOffset])<<8 | int(data[rOffset+1])
			jsonStart := rOffset + 2
			if jsonStart+rLen <= len(data) {
				var rec RecoveryData
				if err := json.Unmarshal(data[jsonStart:jsonStart+rLen], &rec); err == nil && (len(rec.EmailHash) > 0 || rec.AlertsEnabled) {
					return rec, nil
				}
			}
		}
	}

	searchRange := 1024
	if searchRange > len(data) {
		searchRange = len(data)
	}

	for i := len(VaultHeader); i < searchRange; i++ {

		if i+50 > len(data) {
			break
		}

		if data[i] == '{' {

			for l := 50; l < 1000; l++ {
				if i+l > len(data) {
					break
				}
				var rec RecoveryData
				if err := json.Unmarshal(data[i:i+l], &rec); err == nil {

					if (len(rec.EmailHash) > 0 || rec.AlertsEnabled) && (len(rec.KeyHash) > 0 || len(rec.ObfuscatedKey) > 0 || rec.AlertsEnabled) {
						return rec, nil
					}
				}
			}
		}
	}

	return RecoveryData{}, errors.New("could not locate recovery record in vault")
}

func (v *Vault) SetRecoveryEmail(email string) {
	v.RecoveryEmail = email
}

func (v *Vault) ClearRecoveryInfo() {
	v.RecoveryEmail = ""
	v.RecoveryHash = nil
	v.RecoverySlot = nil
	v.RawRecoveryKey = ""
	v.ObfuscatedKey = nil
	v.RecoveryTokenHash = nil
	v.RecoveryTokenExpiry = time.Time{}
	v.RecoveryShareThreshold = 0
	v.RecoveryShareCount = 0
	v.RecoveryShareHashes = nil
	v.RecoveryCodeHashes = nil
	v.RecoveryCodeUsed = nil
	v.RecoveryPasskeyEnabled = false
	v.RecoveryPasskeyUserID = nil
	v.RecoveryPasskeyCred = nil
}

func (v *Vault) SetRecoveryToken(token string, duration time.Duration) {
	h := sha256.Sum256([]byte(token))
	v.RecoveryTokenHash = h[:]
	v.RecoveryTokenExpiry = time.Now().Add(duration)
	v.NeedsRepair = true
}

func (v *Vault) VerifyRecoveryToken(token string) bool {
	if len(v.RecoveryTokenHash) == 0 {
		return false
	}
	if time.Now().After(v.RecoveryTokenExpiry) {
		return false
	}
	h := sha256.Sum256([]byte(token))
	return hmac.Equal(h[:], v.RecoveryTokenHash)
}

func GenerateRecoveryKey() string {
	chars := "ABCDEFGHJKLMNPQRSTUVWXYZ"
	nums := "23456789"

	gen := func(pool string, length int) string {
		res := make([]byte, length)
		for i := 0; i < length; i++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
			res[i] = pool[n.Int64()]
		}
		return string(res)
	}

	part1 := string([]byte{gen(chars, 1)[0], gen(nums, 1)[0], gen(chars, 1)[0], gen(nums, 1)[0]})
	part2 := string([]byte{gen(chars, 1)[0], gen(nums, 1)[0], gen(chars, 1)[0], gen(nums, 1)[0]})
	part3 := gen(chars, 4)
	part4 := gen(nums, 4)

	return fmt.Sprintf("%s-%s-%s-%s", part1, part2, part3, part4)
}

func DeriveRecoveryKey(key string, salt []byte) []byte {
	// Use Argon2id with moderate parameters for recovery key derivation.
	// This replaces the previous single SHA-256 to provide brute-force
	// resistance for the user-written recovery key.
	return argon2.IDKey([]byte(key), salt, 2, 64*1024, 2, 32)
}

func (v *Vault) SetRecoveryKey(key string, salt []byte) error {
	v.RawRecoveryKey = key
	v.RecoverySalt = salt
	rk := DeriveRecoveryKey(key, salt)

	// Use HMAC-SHA256 with vault salt for recovery key hash (prevents
	// length-extension and rainbow-table attacks vs raw SHA-256).
	mac := hmac.New(sha256.New, salt)
	mac.Write(rk)
	v.RecoveryHash = mac.Sum(nil)

	block, err := aes.NewCipher(rk)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for recovery slot: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM for recovery slot: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce for recovery slot: %v", err)
	}

	// Prepend the nonce to the ciphertext so CheckRecoveryKey can extract it.
	ciphertext := gcm.Seal(nil, nonce, v.DEK, nil)
	v.RecoverySlot = append(nonce, ciphertext...)
	return nil
}

func XORRecoveryKey(key string) []byte {

	xorKey := []byte("APM_RECOVERY_OBFUSCATION_SALT_2026")
	data := []byte(key)
	res := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		res[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	return res
}

func DeObfuscateRecoveryKey(obf []byte) string {
	xorKey := []byte("APM_RECOVERY_OBFUSCATION_SALT_2026")
	res := make([]byte, len(obf))
	for i := 0; i < len(obf); i++ {
		res[i] = obf[i] ^ xorKey[i%len(xorKey)]
	}
	return string(res)
}

func tryDeriveRecoveryKey(KDF func(string, []byte) []byte, candidate string, salt []byte, targetHash []byte) ([]byte, bool) {
	rk := KDF(candidate, salt)
	// Use HMAC-SHA256 with salt for key validation (same derivation as
	// SetRecoveryKey). Fall back to raw SHA-256 for legacy vaults.
	mac := hmac.New(sha256.New, salt)
	mac.Write(rk)
	newHash := mac.Sum(nil)
	if hmac.Equal(newHash, targetHash) {
		return rk, true
	}
	// Legacy: raw SHA-256 hash (vaults created before the HMAC fix)
	legacyHash := sha256.Sum256(rk)
	if hmac.Equal(legacyHash[:], targetHash) {
		return rk, true
	}
	return nil, false
}

func deriveRecoveryKeyArgon2(key string, salt []byte) []byte {
	return argon2.IDKey([]byte(key), salt, 2, 64*1024, 2, 32)
}

func deriveRecoveryKeyLegacy(key string, salt []byte) []byte {
	hash := sha256.New()
	hash.Write([]byte(key))
	hash.Write(salt)
	return hash.Sum(nil)
}

func CheckRecoveryKey(data []byte, key string) ([]byte, error) {

	key = strings.TrimSpace(key)
	key = strings.ToUpper(key)

	candidates := []string{key}
	if strings.Contains(key, "-") {
		candidates = append(candidates, strings.ReplaceAll(key, "-", ""))
	} else {

	}

	rec, err := GetVaultRecoveryInfo(data)
	if err != nil {
		return nil, err
	}
	if len(rec.KeyHash) == 0 || len(rec.DEKSlot) == 0 {
		return nil, errors.New("no recovery setup found in vault")
	}

	profile, _, err := GetVaultParams(data)
	if err != nil {
		return nil, err
	}

	offset := len(VaultHeader) + 1

	if offset+2 > len(data) {
		return nil, errors.New("corrupted header")
	}
	pLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + pLen

	if offset+2 > len(data) {
		return nil, errors.New("corrupted header")
	}
	rLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + rLen

	found := false
	var rk []byte

	// KDFs to try, in order of preference (Argon2id first, then legacy SHA-256)
	kdfs := []struct {
		name string
		fn   func(string, []byte) []byte
	}{
		{"argon2id", deriveRecoveryKeyArgon2},
		{"legacy-sha256", deriveRecoveryKeyLegacy},
	}

	for _, candidate := range candidates {
		for _, kdf := range kdfs {
			if len(rec.Salt) > 0 {
				if rk, found = tryDeriveRecoveryKey(kdf.fn, candidate, rec.Salt, rec.KeyHash); found {
					break
				}
			}
		}
		if found {
			break
		}

		// Salt search fallback for shifted vault layouts
		searchStart := offset - 128
		if searchStart < 0 {
			searchStart = 0
		}

		for i := searchStart; i < offset+256; i++ {
			if i+profile.SaltLen+32 > len(data) {
				break
			}
			trialSalt := data[i : i+profile.SaltLen]
			for _, kdf := range kdfs {
				if rk, found = tryDeriveRecoveryKey(kdf.fn, candidate, trialSalt, rec.KeyHash); found {
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		return nil, errors.New("invalid recovery key")
	}

	block, err := aes.NewCipher(rk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var dek []byte
	// Try new format first (nonce prefix), fall back to legacy (zero nonce)
	if len(rec.DEKSlot) >= gcm.NonceSize()+48 {
		nonce := rec.DEKSlot[:gcm.NonceSize()]
		encryptedSlot := rec.DEKSlot[gcm.NonceSize():]
		dek, err = gcm.Open(nil, nonce, encryptedSlot, nil)
	} else {
		// Legacy: zero nonce, full DEKSlot is ciphertext+tag
		nonce := make([]byte, gcm.NonceSize())
		dek, err = gcm.Open(nil, nonce, rec.DEKSlot, nil)
	}
	if err != nil {
		return nil, errors.New("failed to decrypt recovery slot")
	}
	return dek, nil
}

func decryptOldVault(ciphertext []byte, masterPassword string, salt []byte) (*Vault, error) {
	key := DeriveLegacyKey(masterPassword, salt)
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
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: incorrect password or corrupted data")
	}
	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}
	return &vault, nil
}

func EncryptData(plaintext []byte, password string) ([]byte, error) {
	salt, err := GenerateSalt(16)
	if err != nil {
		return nil, err
	}
	p := ProfileStandard
	keys := DeriveKeys(password, salt, p.Time, p.Memory, p.Parallelism)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)

	block, err := aes.NewCipher(keys.EncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Append Encrypt-then-MAC for integrity (defense-in-depth beyond GCM's
	// built-in authentication tag). Use AuthKey from the same KDF derivation.
	hmacPayload := append(salt, ciphertext...)
	signature := CalculateHMAC(hmacPayload, keys.AuthKey)
	return append(hmacPayload, signature...), nil
}

func tryDecryptAESGCM(ciphertext, key []byte) ([]byte, error) {
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
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

func DecryptData(data []byte, password string) ([]byte, error) {
	if len(data) < 16+12 {
		return nil, errors.New("data too short")
	}

	// Try HMAC-verified format first (new). Last 32 bytes are HMAC-SHA256,
	// everything before is salt+ciphertext.
	if len(data) >= 16+12+32 {
		hmacData := data[:len(data)-32]
		storedSig := data[len(data)-32:]
		salt := hmacData[:16]
		ciphertext := hmacData[16:]

		keys := DeriveKeys(password, salt, ProfileStandard.Time, ProfileStandard.Memory, ProfileStandard.Parallelism)
		if VerifyHMAC(hmacData, storedSig, keys.AuthKey) {
			plaintext, err := tryDecryptAESGCM(ciphertext, keys.EncryptionKey)
			Wipe(keys.EncryptionKey)
			Wipe(keys.AuthKey)
			if err == nil {
				return plaintext, nil
			}
		}
		Wipe(keys.EncryptionKey)
		Wipe(keys.AuthKey)
	}

	// Fall back to legacy format (no HMAC). Try standard Argon2id first,
	// then legacy key derivation.
	salt := data[:16]
	ciphertext := data[16:]

	keys := DeriveKeys(password, salt, ProfileStandard.Time, ProfileStandard.Memory, ProfileStandard.Parallelism)
	plaintext, err := tryDecryptAESGCM(ciphertext, keys.EncryptionKey)
	Wipe(keys.EncryptionKey)
	if err == nil {
		return plaintext, nil
	}

	legacyKey := DeriveLegacyKey(password, salt)
	plaintext, err = tryDecryptAESGCM(ciphertext, legacyKey)
	if err == nil {
		return plaintext, nil
	}

	return nil, errors.New("decryption failed: incorrect password or corrupted data")
}

func (v *Vault) logHistory(action, category, identifier string) {
	prevHash := ""
	if n := len(v.History); n > 0 {
		prevHash = v.History[n-1].Hash
	}

	entry := HistoryEntry{
		Timestamp:  time.Now(),
		Action:     action,
		Category:   category,
		Identifier: identifier,
		PrevHash:   prevHash,
	}

	data := fmt.Sprintf("%d:%s:%s:%s:%s", entry.Timestamp.UnixNano(), entry.Action, entry.Category, entry.Identifier, entry.PrevHash)
	hash := sha256.Sum256([]byte(data))
	entry.Hash = hex.EncodeToString(hash[:])

	// Use the derived AuthKey for HMAC signing (not the public salt) to prevent
	// forgery by anyone who can read the vault file. Fall back to v.Salt for
	// legacy vaults where AuthKey is not available.
	signingKey := v.AuthKey
	if len(signingKey) == 0 {
		signingKey = v.Salt
	}
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(entry.Hash))
	entry.Signature = hex.EncodeToString(mac.Sum(nil))

	v.History = append(v.History, entry)

	switch action {
	case "ADD", "EDIT":
		v.TouchSecretTelemetry(category, identifier, true)
	case "GET", "VIEW":
		v.TouchSecretTelemetry(category, identifier, false)
	case "DEL":
		v.RemoveSecretTelemetry(category, identifier)
	}
}

func VerifyHistoryEntrySignature(authKey, salt []byte, entry HistoryEntry) bool {
	if entry.Hash == "" || entry.Signature == "" {
		return false
	}

	legacyData := fmt.Sprintf("%d:%s:%s:%s", entry.Timestamp.UnixNano(), entry.Action, entry.Category, entry.Identifier)
	legacyHash := sha256.Sum256([]byte(legacyData))
	legacyHashHex := hex.EncodeToString(legacyHash[:])

	newData := fmt.Sprintf("%d:%s:%s:%s:%s", entry.Timestamp.UnixNano(), entry.Action, entry.Category, entry.Identifier, entry.PrevHash)
	newHash := sha256.Sum256([]byte(newData))
	newHashHex := hex.EncodeToString(newHash[:])

	if entry.Hash != legacyHashHex && entry.Hash != newHashHex {
		return false
	}

	// Try verifying with AuthKey first (new), fall back to Salt (legacy).
	// This maintains backward compatibility with vaults signed using the old
	// salt-based HMAC while using the stronger derived key for new entries.
	for _, key := range [][]byte{authKey, salt} {
		if len(key) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(entry.Hash))
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(expectedSig), []byte(entry.Signature)) {
			return true
		}
	}
	return false
}

func VerifyHistoryChain(v *Vault) []bool {
	out := make([]bool, len(v.History))
	expectedPrev := ""
	for i, h := range v.History {
		ok := VerifyHistoryEntrySignature(v.AuthKey, v.Salt, h)
		if h.PrevHash != "" && h.PrevHash != expectedPrev {
			ok = false
		}
		out[i] = ok
		expectedPrev = h.Hash
	}
	return out
}

func (v *Vault) AddEntry(account, username, password string) error {
	if v.ActivePolicy.PasswordPolicy.MinLength > 0 {
		if err := v.ActivePolicy.PasswordPolicy.Validate(password); err != nil {
			return err
		}
	}
	for _, e := range v.Entries {
		if e.Account == account && e.Space == v.CurrentSpace {
			return errors.New("account already exists in this space")
		}
	}
	v.Entries = append(v.Entries, Entry{Account: account, Username: username, Password: password, Space: v.CurrentSpace})
	v.logHistory("ADD", "PASSWORD", account)
	return nil
}

func (v *Vault) GetEntry(account string) (Entry, bool) {
	for _, e := range v.Entries {
		if e.Account == account && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.logHistory("GET", "PASSWORD", account)
			return e, true
		}
	}
	return Entry{}, false
}

func (v *Vault) DeleteEntry(account string) bool {
	for i, e := range v.Entries {
		if e.Account == account {
			v.Entries = append(v.Entries[:i], v.Entries[i+1:]...)
			v.logHistory("DEL", "PASSWORD", account)
			return true
		}
	}
	return false
}

func (v *Vault) AddTOTPEntry(account, secret string) error {
	for _, e := range v.TOTPEntries {
		if e.Account == account && e.Space == v.CurrentSpace {
			return errors.New("TOTP account already exists in this space")
		}
	}
	v.TOTPEntries = append(v.TOTPEntries, TOTPEntry{Account: account, Secret: secret, Space: v.CurrentSpace})
	v.logHistory("ADD", "TOTP", account)
	return nil
}

func (v *Vault) GetTOTPEntry(account string) (TOTPEntry, bool) {
	for _, e := range v.TOTPEntries {
		if e.Account == account && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.logHistory("GET", "TOTP", account)
			return e, true
		}
	}
	return TOTPEntry{}, false
}

func (v *Vault) DeleteTOTPEntry(account string) bool {
	for i, e := range v.TOTPEntries {
		if e.Account == account {
			v.TOTPEntries = append(v.TOTPEntries[:i], v.TOTPEntries[i+1:]...)
			v.logHistory("DEL", "TOTP", account)
			return true
		}
	}
	return false
}

func (v *Vault) AddToken(name, token, tType string) error {
	for _, e := range v.Tokens {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("token already exists in this space")
		}
	}
	v.Tokens = append(v.Tokens, TokenEntry{Name: name, Token: token, Type: tType, Space: v.CurrentSpace})
	v.logHistory("ADD", "TOKEN", name)
	return nil
}

func (v *Vault) GetToken(name string) (TokenEntry, bool) {
	for _, e := range v.Tokens {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return TokenEntry{}, false
}

func (v *Vault) DeleteToken(name string) bool {
	for i, e := range v.Tokens {
		if e.Name == name {
			v.Tokens = append(v.Tokens[:i], v.Tokens[i+1:]...)
			v.logHistory("DEL", "TOKEN", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSecureNote(name, content string) error {
	for _, e := range v.SecureNotes {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("note already exists in this space")
		}
	}
	v.SecureNotes = append(v.SecureNotes, SecureNoteEntry{Name: name, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "NOTE", name)
	return nil
}

func (v *Vault) GetSecureNote(name string) (SecureNoteEntry, bool) {
	for _, e := range v.SecureNotes {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return SecureNoteEntry{}, false
}

func (v *Vault) DeleteSecureNote(name string) bool {
	for i, e := range v.SecureNotes {
		if e.Name == name {
			v.SecureNotes = append(v.SecureNotes[:i], v.SecureNotes[i+1:]...)
			v.logHistory("DEL", "NOTE", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddAPIKey(name, service, key string) error {
	for _, e := range v.APIKeys {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("API key already exists in this space")
		}
	}
	v.APIKeys = append(v.APIKeys, APIKeyEntry{Name: name, Service: service, Key: key, Space: v.CurrentSpace})
	v.logHistory("ADD", "APIKEY", name)
	return nil
}

func (v *Vault) GetAPIKey(name string) (APIKeyEntry, bool) {
	for _, e := range v.APIKeys {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return APIKeyEntry{}, false
}

func (v *Vault) DeleteAPIKey(name string) bool {
	for i, e := range v.APIKeys {
		if e.Name == name {
			v.APIKeys = append(v.APIKeys[:i], v.APIKeys[i+1:]...)
			v.logHistory("DEL", "APIKEY", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSSHKey(name, privateKey string) error {
	for _, e := range v.SSHKeys {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("SSH key already exists in this space")
		}
	}
	v.SSHKeys = append(v.SSHKeys, SSHKeyEntry{Name: name, PrivateKey: privateKey, Space: v.CurrentSpace})
	v.logHistory("ADD", "SSHKEY", name)
	return nil
}

func (v *Vault) GetSSHKey(name string) (SSHKeyEntry, bool) {
	for _, e := range v.SSHKeys {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return SSHKeyEntry{}, false
}

func (v *Vault) DeleteSSHKey(name string) bool {
	for i, e := range v.SSHKeys {
		if e.Name == name {
			v.SSHKeys = append(v.SSHKeys[:i], v.SSHKeys[i+1:]...)
			v.logHistory("DEL", "SSHKEY", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddWiFi(ssid, password, security string) error {
	for _, e := range v.WiFiCredentials {
		if e.SSID == ssid && e.Space == v.CurrentSpace {
			return errors.New("WiFi already exists in this space")
		}
	}
	v.WiFiCredentials = append(v.WiFiCredentials, WiFiEntry{SSID: ssid, Password: password, SecurityType: security, Space: v.CurrentSpace})
	v.logHistory("ADD", "WIFI", ssid)
	return nil
}

func (v *Vault) GetWiFi(ssid string) (WiFiEntry, bool) {
	for _, e := range v.WiFiCredentials {
		if e.SSID == ssid && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return WiFiEntry{}, false
}

func (v *Vault) DeleteWiFi(ssid string) bool {
	for i, e := range v.WiFiCredentials {
		if e.SSID == ssid && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.WiFiCredentials = append(v.WiFiCredentials[:i], v.WiFiCredentials[i+1:]...)
			v.logHistory("DEL", "WIFI", ssid)
			return true
		}
	}
	return false
}

func (v *Vault) AddRecoveryCode(service string, codes []string) error {
	for _, e := range v.RecoveryCodeItems {
		if e.Service == service && e.Space == v.CurrentSpace {
			return errors.New("recovery codes for service already exist in this space")
		}
	}
	v.RecoveryCodeItems = append(v.RecoveryCodeItems, RecoveryCodeEntry{Service: service, Codes: codes, Space: v.CurrentSpace})
	v.logHistory("ADD", "RECOVERY", service)
	return nil
}

func (v *Vault) GetRecoveryCode(service string) (RecoveryCodeEntry, bool) {
	for _, e := range v.RecoveryCodeItems {
		if e.Service == service && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return RecoveryCodeEntry{}, false
}

func (v *Vault) DeleteRecoveryCode(service string) bool {
	for i, e := range v.RecoveryCodeItems {
		if e.Service == service && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.RecoveryCodeItems = append(v.RecoveryCodeItems[:i], v.RecoveryCodeItems[i+1:]...)
			v.logHistory("DEL", "RECOVERY", service)
			return true
		}
	}
	return false
}

func (v *Vault) AddCertificate(label, cert, key, issuer string, expiry time.Time) error {
	for _, e := range v.Certificates {
		if e.Label == label && e.Space == v.CurrentSpace {
			return errors.New("certificate already exists in this space")
		}
	}
	v.Certificates = append(v.Certificates, CertificateEntry{Label: label, CertData: cert, PrivateKey: key, Issuer: issuer, Expiry: expiry, Space: v.CurrentSpace})
	v.logHistory("ADD", "CERTIFICATE", label)
	return nil
}

func (v *Vault) GetCertificate(label string) (CertificateEntry, bool) {
	for _, e := range v.Certificates {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return CertificateEntry{}, false
}

func (v *Vault) DeleteCertificate(label string) bool {
	for i, e := range v.Certificates {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.Certificates = append(v.Certificates[:i], v.Certificates[i+1:]...)
			v.logHistory("DEL", "CERTIFICATE", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddBankingItem(label, bType, details, cvv, expiry string) error {
	for _, e := range v.BankingItems {
		if e.Label == label && e.Space == v.CurrentSpace {
			return errors.New("banking item already exists in this space")
		}
	}
	v.BankingItems = append(v.BankingItems, BankingEntry{Label: label, Type: bType, Details: details, CVV: cvv, Expiry: expiry, Space: v.CurrentSpace})
	v.logHistory("ADD", "BANKING", label)
	return nil
}

func (v *Vault) GetBankingItem(label string) (BankingEntry, bool) {
	for _, e := range v.BankingItems {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return BankingEntry{}, false
}

func (v *Vault) DeleteBankingItem(label string) bool {
	for i, e := range v.BankingItems {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.BankingItems = append(v.BankingItems[:i], v.BankingItems[i+1:]...)
			v.logHistory("DEL", "BANKING", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddDocument(name, fileName string, content []byte, password string, tags []string, expiry string) error {
	for _, e := range v.Documents {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("document already exists in this space")
		}
	}
	v.Documents = append(v.Documents, DocumentEntry{Name: name, FileName: fileName, Content: content, Password: password, Tags: tags, Expiry: expiry, Space: v.CurrentSpace})
	v.logHistory("ADD", "DOCUMENT", name)
	return nil
}

func (v *Vault) GetDocument(name string) (DocumentEntry, bool) {
	for _, e := range v.Documents {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return DocumentEntry{}, false
}

func (v *Vault) DeleteDocument(name string) bool {
	for i, e := range v.Documents {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.Documents = append(v.Documents[:i], v.Documents[i+1:]...)
			v.logHistory("DEL", "DOCUMENT", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddAudio(name, fileName string, content []byte) error {
	for _, e := range v.AudioFiles {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("audio file already exists in this space")
		}
	}
	v.AudioFiles = append(v.AudioFiles, AudioEntry{Name: name, FileName: fileName, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "AUDIO", name)
	return nil
}

func (v *Vault) GetAudio(name string) (AudioEntry, bool) {
	for _, e := range v.AudioFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return AudioEntry{}, false
}

func (v *Vault) DeleteAudio(name string) bool {
	for i, e := range v.AudioFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.AudioFiles = append(v.AudioFiles[:i], v.AudioFiles[i+1:]...)
			v.logHistory("DEL", "AUDIO", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddVideo(name, fileName string, content []byte) error {
	for _, e := range v.VideoFiles {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("video file already exists in this space")
		}
	}
	v.VideoFiles = append(v.VideoFiles, VideoEntry{Name: name, FileName: fileName, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "VIDEO", name)
	return nil
}

func (v *Vault) GetVideo(name string) (VideoEntry, bool) {
	for _, e := range v.VideoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return VideoEntry{}, false
}

func (v *Vault) DeleteVideo(name string) bool {
	for i, e := range v.VideoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.VideoFiles = append(v.VideoFiles[:i], v.VideoFiles[i+1:]...)
			v.logHistory("DEL", "VIDEO", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddPhoto(name, fileName string, content []byte) error {
	for _, e := range v.PhotoFiles {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("photo file already exists in this space")
		}
	}
	v.PhotoFiles = append(v.PhotoFiles, PhotoEntry{Name: name, FileName: fileName, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "PHOTO", name)
	return nil
}

func (v *Vault) GetPhoto(name string) (PhotoEntry, bool) {
	for _, e := range v.PhotoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return PhotoEntry{}, false
}

func (v *Vault) DeletePhoto(name string) bool {
	for i, e := range v.PhotoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.PhotoFiles = append(v.PhotoFiles[:i], v.PhotoFiles[i+1:]...)
			v.logHistory("DEL", "PHOTO", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddGovID(g GovIDEntry) error {
	for _, e := range v.GovIDs {
		if e.IDNumber == g.IDNumber && e.Type == g.Type && e.Space == v.CurrentSpace {
			return errors.New("government ID already exists in this space")
		}
	}
	g.Space = v.CurrentSpace
	v.GovIDs = append(v.GovIDs, g)
	v.logHistory("ADD", "GOVID", g.IDNumber)
	return nil
}

func (v *Vault) DeleteGovID(idNum string) bool {
	for i, e := range v.GovIDs {
		if e.IDNumber == idNum && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.GovIDs = append(v.GovIDs[:i], v.GovIDs[i+1:]...)
			v.logHistory("DEL", "GOVID", idNum)
			return true
		}
	}
	return false
}

func (v *Vault) AddMedicalRecord(m MedicalRecordEntry) error {
	m.Space = v.CurrentSpace
	v.MedicalRecords = append(v.MedicalRecords, m)
	v.logHistory("ADD", "MEDICAL", m.Label)
	return nil
}

func (v *Vault) DeleteMedicalRecord(label string) bool {
	for i, e := range v.MedicalRecords {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.MedicalRecords = append(v.MedicalRecords[:i], v.MedicalRecords[i+1:]...)
			v.logHistory("DEL", "MEDICAL", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddTravelDoc(t TravelEntry) error {
	t.Space = v.CurrentSpace
	v.TravelDocs = append(v.TravelDocs, t)
	v.logHistory("ADD", "TRAVEL", t.Label)
	return nil
}

func (v *Vault) DeleteTravelDoc(label string) bool {
	for i, e := range v.TravelDocs {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.TravelDocs = append(v.TravelDocs[:i], v.TravelDocs[i+1:]...)
			v.logHistory("DEL", "TRAVEL", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddContact(c ContactEntry) error {
	c.Space = v.CurrentSpace
	v.Contacts = append(v.Contacts, c)
	v.logHistory("ADD", "CONTACT", c.Name)
	return nil
}

func (v *Vault) DeleteContact(name string) bool {
	for i, e := range v.Contacts {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.Contacts = append(v.Contacts[:i], v.Contacts[i+1:]...)
			v.logHistory("DEL", "CONTACT", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddCloudCredential(c CloudCredentialEntry) error {
	c.Space = v.CurrentSpace
	v.CloudCredentialsItems = append(v.CloudCredentialsItems, c)
	v.logHistory("ADD", "CLOUDCRED", c.Label)
	return nil
}

func (v *Vault) DeleteCloudCredential(label string) bool {
	for i, e := range v.CloudCredentialsItems {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.CloudCredentialsItems = append(v.CloudCredentialsItems[:i], v.CloudCredentialsItems[i+1:]...)
			v.logHistory("DEL", "CLOUDCRED", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddK8sSecret(k K8sSecretEntry) error {
	k.Space = v.CurrentSpace
	v.K8sSecrets = append(v.K8sSecrets, k)
	v.logHistory("ADD", "K8S", k.Name)
	return nil
}

func (v *Vault) DeleteK8sSecret(name string) bool {
	for i, e := range v.K8sSecrets {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.K8sSecrets = append(v.K8sSecrets[:i], v.K8sSecrets[i+1:]...)
			v.logHistory("DEL", "K8S", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddDockerRegistry(d DockerRegistryEntry) error {
	d.Space = v.CurrentSpace
	v.DockerRegistries = append(v.DockerRegistries, d)
	v.logHistory("ADD", "DOCKER", d.Name)
	return nil
}

func (v *Vault) DeleteDockerRegistry(name string) bool {
	for i, e := range v.DockerRegistries {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.DockerRegistries = append(v.DockerRegistries[:i], v.DockerRegistries[i+1:]...)
			v.logHistory("DEL", "DOCKER", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSSHConfig(s SSHConfigEntry) error {
	s.Space = v.CurrentSpace
	v.SSHConfigs = append(v.SSHConfigs, s)
	v.logHistory("ADD", "SSHCONFIG", s.Alias)
	return nil
}

func (v *Vault) DeleteSSHConfig(alias string) bool {
	for i, e := range v.SSHConfigs {
		if e.Alias == alias && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.SSHConfigs = append(v.SSHConfigs[:i], v.SSHConfigs[i+1:]...)
			v.logHistory("DEL", "SSHCONFIG", alias)
			return true
		}
	}
	return false
}

func (v *Vault) AddCICDSecret(c CICDSecretEntry) error {
	c.Space = v.CurrentSpace
	v.CICDSecrets = append(v.CICDSecrets, c)
	v.logHistory("ADD", "CICD", c.Name)
	return nil
}

func (v *Vault) DeleteCICDSecret(name string) bool {
	for i, e := range v.CICDSecrets {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.CICDSecrets = append(v.CICDSecrets[:i], v.CICDSecrets[i+1:]...)
			v.logHistory("DEL", "CICD", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSoftwareLicense(s SoftwareLicenseEntry) error {
	s.Space = v.CurrentSpace
	v.SoftwareLicenses = append(v.SoftwareLicenses, s)
	v.logHistory("ADD", "LICENSE", s.ProductName)
	return nil
}

func (v *Vault) DeleteSoftwareLicense(product string) bool {
	for i, e := range v.SoftwareLicenses {
		if e.ProductName == product && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.SoftwareLicenses = append(v.SoftwareLicenses[:i], v.SoftwareLicenses[i+1:]...)
			v.logHistory("DEL", "LICENSE", product)
			return true
		}
	}
	return false
}

func (v *Vault) AddLegalContract(l LegalContractEntry) error {
	l.Space = v.CurrentSpace
	v.LegalContracts = append(v.LegalContracts, l)
	v.logHistory("ADD", "CONTRACT", l.Name)
	return nil
}

func (v *Vault) DeleteLegalContract(name string) bool {
	for i, e := range v.LegalContracts {
		if e.Name == name {
			v.LegalContracts = append(v.LegalContracts[:i], v.LegalContracts[i+1:]...)
			v.logHistory("DEL", "CONTRACT", name)
			return true
		}
	}
	return false
}

type SearchResult struct {
	Type       string
	Identifier string
	Data       interface{}
	Space      string
}

func (v *Vault) SearchAll(query string) []SearchResult {
	var results []SearchResult
	query = strings.ToLower(query)

	matchSpace := func(ns string) bool {
		current := v.CurrentSpace
		if current == "" {
			current = "default"
		}
		target := ns
		if target == "" {
			target = "default"
		}
		return current == target
	}

	for _, e := range v.Entries {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Account), query)) {
			results = append(results, SearchResult{"Password", e.Account, e, e.Space})
		}
	}
	for _, e := range v.TOTPEntries {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Account), query)) {
			results = append(results, SearchResult{"TOTP", e.Account, e, e.Space})
		}
	}
	for _, e := range v.Tokens {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Token", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SecureNotes {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Note", e.Name, e, e.Space})
		}
	}
	for _, e := range v.APIKeys {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"API Key", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SSHKeys {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"SSH Key", e.Name, e, e.Space})
		}
	}
	for _, e := range v.WiFiCredentials {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.SSID), query)) {
			results = append(results, SearchResult{"Wi-Fi", e.SSID, e, e.Space})
		}
	}
	for _, e := range v.RecoveryCodeItems {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Service), query)) {
			results = append(results, SearchResult{"Recovery Codes", e.Service, e, e.Space})
		}
	}
	for _, e := range v.Certificates {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Certificate", e.Label, e, e.Space})
		}
	}
	for _, e := range v.BankingItems {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Banking", e.Label, e, e.Space})
		}
	}
	for _, e := range v.Documents {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Document", e.Name, e, e.Space})
		}
	}
	for _, e := range v.AudioFiles {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Audio", e.Name, e, e.Space})
		}
	}
	for _, e := range v.VideoFiles {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Video", e.Name, e, e.Space})
		}
	}
	for _, e := range v.PhotoFiles {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Photo", e.Name, e, e.Space})
		}
	}
	for _, e := range v.GovIDs {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.IDNumber), query) || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Government ID", e.IDNumber, e, e.Space})
		}
	}
	for _, e := range v.MedicalRecords {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Medical Record", e.Label, e, e.Space})
		}
	}
	for _, e := range v.TravelDocs {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Travel", e.Label, e, e.Space})
		}
	}
	for _, e := range v.Contacts {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Contact", e.Name, e, e.Space})
		}
	}
	for _, e := range v.CloudCredentialsItems {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Cloud Credentials", e.Label, e, e.Space})
		}
	}
	for _, e := range v.K8sSecrets {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Kubernetes Secret", e.Name, e, e.Space})
		}
	}
	for _, e := range v.DockerRegistries {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Docker Registry", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SSHConfigs {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Alias), query)) {
			results = append(results, SearchResult{"SSH Config", e.Alias, e, e.Space})
		}
	}
	for _, e := range v.CICDSecrets {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"CI/CD Secret", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SoftwareLicenses {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.ProductName), query)) {
			results = append(results, SearchResult{"Software License", e.ProductName, e, e.Space})
		}
	}
	for _, e := range v.LegalContracts {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Legal Contract", e.Name, e, e.Space})
		}
	}
	return results
}

func GetDecoyVault() *Vault {
	v := &Vault{
		Salt:   make([]byte, 16),
		Spaces: []string{"default", "work", "personal"},
	}
	rand.Read(v.Salt)

	for i := 0; i < 15; i++ {
		acc, _ := GenerateRandomWords()
		user, _ := GenerateRandomWords()
		pass, _ := GenerateRandomHex(16)
		v.Entries = append(v.Entries, Entry{
			Account:  acc,
			Username: strings.ToLower(user),
			Password: pass,
			Space:    "default",
		})
	}

	for i := 0; i < 5; i++ {
		acc, _ := GenerateRandomWords()
		sec, _ := GenerateRandomHex(20)
		v.TOTPEntries = append(v.TOTPEntries, TOTPEntry{
			Account: acc,
			Secret:  sec,
		})
	}

	for i := 0; i < 5; i++ {
		name, _ := GenerateRandomWords()
		v.SecureNotes = append(v.SecureNotes, SecureNoteEntry{
			Name:    name,
			Content: "This is a decoy note containing sensitive-looking information for testing purposes.",
		})
	}

	return v
}
