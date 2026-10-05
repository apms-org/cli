package apm

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// UnlockResult represents the result of an unlock attempt
type UnlockResult struct {
	MasterPassword string
	Vault          *Vault
	ReadOnly       bool
	IsEphemeral    bool
}

// AttemptUnlockWithSession tries to unlock the vault using existing sessions or ephemeral IDs
func AttemptUnlockWithSession(vaultPath string) (*UnlockResult, error) {
	if !VaultExists(vaultPath) {
		return nil, fmt.Errorf("vault not found")
	}

	if ephID := strings.TrimSpace(os.Getenv("APM_EPHEMERAL_ID")); ephID != "" {
		eph, err := ValidateEphemeralSession(ephID, os.Getpid(), strings.TrimSpace(os.Getenv("APM_EPHEMERAL_AGENT")))
		if err == nil {
			data, lerr := LoadVault(vaultPath)
			if lerr == nil {
				vault, derr := DecryptVault(data, eph.MasterPassword, 1)
				if derr == nil {
					return &UnlockResult{
						MasterPassword: eph.MasterPassword,
						Vault:          vault,
						ReadOnly:       eph.Scope == "read",
						IsEphemeral:    true,
					}, nil
				}
			}
		}
	}

	if session, err := GetSession(); err == nil {
		data, err := LoadVault(vaultPath)
		if err == nil {
			localFailures := GetFailureCount()
			if session.ReadOnly && localFailures >= 6 {
				return &UnlockResult{
					MasterPassword: session.MasterPassword,
					Vault:          GetDecoyVault(),
					ReadOnly:       true,
					IsEphemeral:    false,
				}, nil
			}

			vault, err := DecryptVault(data, session.MasterPassword, 1)
			if err == nil {
				if vault.NeedsRepair && !vault.IsNewerFormat() {
					updatedData, _ := EncryptVault(vault, session.MasterPassword)
					SaveVault(vaultPath, updatedData)
				}
				return &UnlockResult{
					MasterPassword: session.MasterPassword,
					Vault:          vault,
					ReadOnly:       session.ReadOnly,
					IsEphemeral:    false,
				}, nil
			}
		}
		KillSession()
	}

	return nil, fmt.Errorf("no active session")
}

// UnlockWithPassword attempts to unlock the vault with the provided password
func UnlockWithPassword(vaultPath, password string) (*UnlockResult, error) {
	data, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}

	localFailures := GetFailureCount()
	if localFailures >= 9 {
		return nil, fmt.Errorf("vault permanently locked due to suspected breach")
	}

	if localFailures >= 6 {

		TrackFailure()
		CreateSession(password, 1*time.Hour, true, 15*time.Minute)
		return &UnlockResult{
			MasterPassword: password,
			Vault:          GetDecoyVault(),
			ReadOnly:       true,
			IsEphemeral:    false,
		}, nil
	}

	vault, err := DecryptVault(data, password, 1)
	if err != nil {
		TrackFailure()

		if rec, err := GetVaultRecoveryInfo(data); err == nil && rec.AlertsEnabled && rec.AlertEmail != "" {
			tempVault := &Vault{
				AlertEmail:    rec.AlertEmail,
				AlertsEnabled: rec.AlertsEnabled,
				SecurityLevel: rec.SecurityLevel,
			}
			SendAlert(tempVault, LevelCritical, "BREACH ATTEMPT", fmt.Sprintf("Failed unlock attempt detected"))
		}
		return nil, err
	}

	ClearFailures()
	vault.FailedAttempts = 0
	vault.EmergencyMode = false

	// A vault from a newer engine opens read-only, so it is not rewritten here.
	if !vault.IsNewerFormat() {
		updatedData, _ := EncryptVault(vault, password)
		SaveVault(vaultPath, updatedData)
	}

	CreateSession(password, 1*time.Hour, false, 15*time.Minute)

	return &UnlockResult{
		MasterPassword: password,
		Vault:          vault,
		ReadOnly:       false,
		IsEphemeral:    false,
	}, nil
}
