package apm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// An MCP client must not be able to commit its own vault change: write tools
// only queue a request, and passing tx_id with approve=true changes nothing.
func TestMCPWriteToolsCannotSelfApprove(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("APPDATA", filepath.Join(dir, "AppData"))
	t.Setenv("APM_STATE_DIR", filepath.Join(dir, "state"))
	vaultPath := filepath.Join(dir, "vault.dat")

	token, err := GenerateMCPToken("test", []string{"add_entry", "delete_entry", "edit_entry"}, 0)
	if err != nil {
		t.Fatalf("GenerateMCPToken: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverT, clientT := mcp.NewInMemoryTransports()
	go func() { _ = StartMCPServer(token, vaultPath, serverT) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	call := func(tool string, args map[string]any) string {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if res.IsError {
			t.Fatalf("%s returned an error: %+v", tool, res.Content)
		}
		return res.Content[0].(*mcp.TextContent).Text
	}

	out := call("add_entry", map[string]any{"type": "password", "name": "example", "username": "me", "password": "pw"})
	if !strings.Contains(out, "Waiting for approval") {
		t.Fatalf("add_entry did not ask for approval: %q", out)
	}
	txs, err := ListMCPTransactions(0)
	if err != nil || len(txs) != 1 {
		t.Fatalf("expected 1 pending transaction, got %d (%v)", len(txs), err)
	}
	first := txs[0].ID

	for _, tool := range []string{"add_entry", "edit_entry", "delete_entry"} {
		call(tool, map[string]any{"type": "password", "name": "example", "password": "pw2", "tx_id": first, "approve": true})
	}

	txs, err = ListMCPTransactions(0)
	if err != nil {
		t.Fatalf("ListMCPTransactions: %v", err)
	}
	if len(txs) != 4 {
		t.Fatalf("expected 4 pending transactions, got %d", len(txs))
	}
	for _, tx := range txs {
		if tx.Status != "pending" {
			t.Fatalf("transaction %s (%s) is %s; only the user may commit it", tx.ID, tx.Tool, tx.Status)
		}
	}
	if _, err := os.Stat(vaultPath); !os.IsNotExist(err) {
		t.Fatalf("vault file was written by an MCP client: %v", err)
	}
}

func TestMCPToolPermissionsHaveNoInstallTools(t *testing.T) {
	for _, p := range MCPToolPermissions() {
		if p == "install_apm" || p == "check_installation" {
			t.Fatalf("%s should not be an MCP tool", p)
		}
	}
}
