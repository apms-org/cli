package apm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const formatTestPassword = "ValidPass123!"

// linkedTOTPVault holds a login and its standalone code, which decrypt-time
// repair would normally fold together.
func linkedTOTPVault(t *testing.T) *Vault {
	t.Helper()
	v := &Vault{Profile: "standard", Spaces: []string{"default"}}
	if err := v.AddEntry("github", "alice", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := v.AddTOTPEntry("github", testTOTP); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNewerVaultIsNotSavedOrRepaired(t *testing.T) {
	v := linkedTOTPVault(t)
	v.FormatRevision = VaultFormatRevision + 1
	// Seal it the way a newer engine would, bypassing this engine's guard.
	data, err := encryptVaultPayload(v, formatTestPassword)
	if err != nil {
		t.Fatal(err)
	}

	out, err := DecryptVault(data, formatTestPassword, 1)
	if err != nil {
		t.Fatalf("a newer vault must still open: %v", err)
	}
	if !out.IsNewerFormat() || out.FormatRevision != VaultFormatRevision+1 {
		t.Fatalf("expected a newer vault, got revision %d", out.FormatRevision)
	}
	if out.NeedsRepair {
		t.Fatal("a newer vault must not be flagged for repair")
	}
	if len(out.TOTPEntries) != 1 || out.Entries[0].TOTP != "" {
		t.Fatal("decrypt-time repair must not modify a newer vault")
	}

	if _, err := EncryptVault(out, formatTestPassword); !errors.Is(err, ErrVaultNewer) {
		t.Fatalf("expected ErrVaultNewer, got %v", err)
	}
	if out.FormatRevision != VaultFormatRevision+1 {
		t.Fatal("a refused save must not restamp the revision")
	}

	// Callers that drop the EncryptVault error must not truncate the file.
	path := filepath.Join(t.TempDir(), "vault.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	enc, _ := EncryptVault(out, formatTestPassword)
	if err := SaveVault(path, enc); err == nil {
		t.Fatal("saving an empty vault should fail")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatal("vault file changed after a refused save")
	}
}

func TestOlderVaultSavesAndIsStamped(t *testing.T) {
	v := linkedTOTPVault(t)
	if v.FormatRevision != 0 {
		t.Fatalf("new vault should start unrevisioned, got %d", v.FormatRevision)
	}
	data, err := EncryptVault(v, formatTestPassword)
	if err != nil {
		t.Fatalf("an older vault must save: %v", err)
	}
	if v.FormatRevision != VaultFormatRevision {
		t.Fatalf("save should stamp revision %d, got %d", VaultFormatRevision, v.FormatRevision)
	}
	out, err := DecryptVault(data, formatTestPassword, 1)
	if err != nil {
		t.Fatal(err)
	}
	if out.FormatRevision != VaultFormatRevision || out.IsNewerFormat() {
		t.Fatalf("stamped revision not stored in the payload: %d", out.FormatRevision)
	}
	if !out.NeedsRepair || out.Entries[0].TOTP != testTOTP {
		t.Fatal("repair should still run on a vault this engine can write")
	}
	if _, err := EncryptVault(out, formatTestPassword); err != nil {
		t.Fatalf("a current vault must save again: %v", err)
	}
}
