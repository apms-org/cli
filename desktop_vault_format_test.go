package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	src "github.com/aaravmaloo/apm/src"
)

// TestDesktopNewerVaultIsReadOnly unlocks a vault written by a newer engine and
// checks the backend reports it and refuses every write with vault_newer.
func TestDesktopNewerVaultIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for k, v := range map[string]string{"HOME": dir, "APM_STATE_DIR": dir, "APM_SESSION_ID": "", "APM_EPHEMERAL_ID": "", "APM_DESKTOP_NO_TOUCHID": "1", "APM_ICONS_OFFLINE": "1"} {
		t.Setenv(k, v)
	}
	prevPath := vaultPath
	vaultPath = filepath.Join(dir, "vault.dat")
	t.Cleanup(func() { vaultPath = prevPath })

	const pw = "ValidPass123!"
	v := &src.Vault{Profile: "standard", Spaces: []string{"default"}}
	if err := v.AddEntry("github", "alice", "s3cret"); err != nil {
		t.Fatal(err)
	}
	data, err := src.EncryptVault(v, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	newer, err := src.DecryptVault(data, pw, 1)
	if err != nil {
		t.Fatal(err)
	}
	// What a newer engine would have written; repair must not touch it.
	newer.FormatRevision = src.VaultFormatRevision + 1
	newer.NeedsRepair = true

	s := newDesktopServer(nil)
	s.sink = func(string, any) {}
	res := s.finishUnlock(pw, newer, "test", false)

	snap := res["snapshot"].(map[string]any)
	if snap["newerFormat"] != true || snap["readonly"] != true {
		t.Fatalf("snapshot should report a read-only newer vault: newerFormat=%v readonly=%v", snap["newerFormat"], snap["readonly"])
	}
	if snap["formatRevision"] != src.VaultFormatRevision+1 || snap["engineRevision"] != src.VaultFormatRevision {
		t.Fatalf("unexpected revisions: %v / %v", snap["formatRevision"], snap["engineRevision"])
	}
	status, err := hVaultStatus(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st := status.(map[string]any); st["newerFormat"] != true || st["readonly"] != true {
		t.Fatalf("vault.status should report a read-only newer vault: %v", st)
	}

	add, _ := json.Marshal(map[string]any{"type": "password", "f": map[string]any{"account": "new", "password": "pw-1234567"}})
	for _, method := range []string{"item.add", "space.add"} {
		params := json.RawMessage(add)
		if method == "space.add" {
			params = json.RawMessage(`{"name":"Work"}`)
		}
		_, err := desktopMethods[method].fn(s, params)
		var re *rpcError
		if !errors.As(err, &re) || re.Code != "vault_newer" {
			t.Fatalf("%s: expected vault_newer, got %v", method, err)
		}
	}
	// Even a save that slipped past requireWritable maps to vault_newer.
	if re := mapGoError(s.save("test")); re.Code != "vault_newer" {
		t.Fatalf("save: expected vault_newer, got %s", re.Code)
	}
	if got, _ := os.ReadFile(vaultPath); !bytes.Equal(got, data) {
		t.Fatal("the newer vault file was modified")
	}

	// Locked: the revision is unknown, so newerFormat reports false.
	s.dropKey()
	status, _ = hVaultStatus(s, nil)
	if status.(map[string]any)["newerFormat"] != false {
		t.Fatal("a locked vault should report newerFormat false")
	}
}
