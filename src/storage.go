package apm

import (
	"errors"
	"os"
)

func SaveVault(path string, data []byte) error {
	// A failed EncryptVault (for example ErrVaultNewer) yields no data; never
	// let a caller that ignored that error truncate the vault file.
	if len(data) == 0 {
		return errors.New("refusing to write an empty vault")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	_ = RecordLGitCommit(path, data, "SAVE")
	return nil
}

func LoadVault(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	return os.ReadFile(path)
}

func VaultExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
