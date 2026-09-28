package apm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("failed to create dir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func buildPMBinary(t *testing.T, outPath string) {
	t.Helper()

	cmd := exec.Command("go", "build", "-o", outPath, "..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build pm binary: %v\n%s", err, string(output))
	}
}

func runCommand(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, string(output))
	}
	return string(output)
}

func TestCLISmoke_SetupAndProfileCurrent(t *testing.T) {
	tempDir := t.TempDir()

	exe := "pm"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	pmBinary := filepath.Join(tempDir, exe)
	buildPMBinary(t, pmBinary)

	helpOut := runCommand(t, exec.Command(pmBinary, "--help"))
	if !strings.Contains(helpOut, "setup") {
		t.Fatalf("expected help output to include setup command, output:\n%s", helpOut)
	}

	vaultPath := filepath.Join(tempDir, "vault.dat")
	sessionID := "cli_smoke_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	env := append(os.Environ(), "APM_SESSION_ID="+sessionID)

	setupCmd := exec.Command(pmBinary, "--vault", vaultPath, "setup", "--non-interactive")
	setupCmd.Env = env
	setupCmd.Stdin = strings.NewReader("ValidPass123!\n")
	setupOut := runCommand(t, setupCmd)
	if !strings.Contains(setupOut, "Setup completed successfully.") {
		t.Fatalf("expected setup success output, got:\n%s", setupOut)
	}

	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("expected vault file at %s: %v", vaultPath, err)
	}

	profileCmd := exec.Command(pmBinary, "--vault", vaultPath, "profile", "current")
	profileCmd.Env = env
	profileCmd.Stdin = strings.NewReader("ValidPass123!\n")
	profileOut := runCommand(t, profileCmd)
	if !strings.Contains(profileOut, "Current profile") {
		t.Fatalf("expected profile output, got:\n%s", profileOut)
	}
}

func TestCLISmoke_LoadedSections(t *testing.T) {
	tempDir := t.TempDir()

	exe := "pm"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	pmBinary := filepath.Join(tempDir, exe)
	buildPMBinary(t, pmBinary)

	vaultPath := filepath.Join(tempDir, "vault.dat")
	loadedOut := runCommand(t, exec.Command(pmBinary, "--vault", vaultPath, "loaded"))

	for _, section := range []string{"[policies]", "[.apmignore]"} {
		if !strings.Contains(loadedOut, section) {
			t.Fatalf("expected %s in loaded output, got:\n%s", section, loadedOut)
		}
	}
	if strings.Contains(loadedOut, "[plugins]") {
		t.Fatalf("expected no [plugins] section in loaded output, got:\n%s", loadedOut)
	}
}

func TestCLISmoke_PluginsRemoved(t *testing.T) {
	tempDir := t.TempDir()

	exe := "pm"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	pmBinary := filepath.Join(tempDir, exe)
	buildPMBinary(t, pmBinary)

	writeFile(t, filepath.Join(tempDir, "plugins", "hello_vault", "plugin.json"), `{"name":"hello_vault","commands":{"hello":{"steps":[{"op":"s:out","args":["hello-from-plugin"]}]}}}`)

	vaultPath := filepath.Join(tempDir, "vault.dat")
	for _, args := range [][]string{{"plugins"}, {"hello"}} {
		out, _ := exec.Command(pmBinary, append([]string{"--vault", vaultPath}, args...)...).CombinedOutput()
		if !strings.Contains(string(out), `unknown command "`+args[0]+`"`) {
			t.Fatalf("expected unknown command error for pm %s, got:\n%s", args[0], string(out))
		}
	}

	helpOut := runCommand(t, exec.Command(pmBinary, "--vault", vaultPath, "--help"))
	commandList, _, _ := strings.Cut(helpOut, "Flags:")
	if strings.Contains(strings.ToLower(commandList), "plugin") {
		t.Fatalf("expected no plugin commands in help, got:\n%s", helpOut)
	}
}

func TestCLISmoke_AddWithTypeArgumentCaseInsensitive(t *testing.T) {
	tempDir := t.TempDir()

	exe := "pm"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	pmBinary := filepath.Join(tempDir, exe)
	buildPMBinary(t, pmBinary)

	vaultPath := filepath.Join(tempDir, "vault.dat")
	setupCmd := exec.Command(pmBinary, "--vault", vaultPath, "setup", "--non-interactive")
	setupCmd.Stdin = strings.NewReader("ValidPass123!\n")
	setupOut := runCommand(t, setupCmd)
	if !strings.Contains(setupOut, "Setup completed successfully.") {
		t.Fatalf("expected setup success output, got:\n%s", setupOut)
	}

	addCmd := exec.Command(pmBinary, "--vault", vaultPath, "add", "PASSWORD")
	addCmd.Stdin = strings.NewReader("ValidPass123!\nexample_account\nexample_user\n\n")
	addOut := runCommand(t, addCmd)
	if !strings.Contains(addOut, "Entry saved.") {
		t.Fatalf("expected add command to save entry, got:\n%s", addOut)
	}
}
