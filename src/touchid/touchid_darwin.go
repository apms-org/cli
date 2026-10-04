//go:build darwin

package touchid

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const touchIDReasonEnv = "APM_TOUCHID_REASON"

// authScriptTemplate is the JXA script template. It reads the reason string
// from the environment variable APM_TOUCHID_REASON using ObjC bridging,
// avoiding any shell escaping or URL-encoding issues.
const authScriptTemplate = `ObjC.import('LocalAuthentication');
ObjC.import('AppKit');
// Activate the process as an active app before prompting: without this the
// Touch ID dialog flashes instantly with no native animation.
$.NSApplication.sharedApplication.activateIgnoringOtherApps(true);
var ctx = $.LAContext.alloc.init;
var errRef = Ref();
if (!ctx.canEvaluatePolicyError(1, errRef)) {
  "false:Touch ID not available";
} else {
  var done = false, ok = false;
  var reasonVal = $.NSProcessInfo.processInfo.environment.objectForKey($("APM_TOUCHID_REASON"));
  var reason = reasonVal ? reasonVal.js : "Authenticate";
  ctx.evaluatePolicyLocalizedReasonReply(1, $(reason), function(success) {
    ok = success;
    done = true;
  });
  // Tight 0.1s spin keeps the run loop responsive so the animation renders.
  while (!done) { $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.1)); }
  ok ? "true" : "false:auth failed";
}`

// availableScript is a static script that checks if Touch ID is available.
const availableScript = `ObjC.import('LocalAuthentication');
var ctx = $.LAContext.alloc.init;
var err = Ref();
ctx.canEvaluatePolicyError(1, err) ? "true" : "false";`

// runJXAScript writes script to a temp file and runs osascript on it.
// The env var APM_TOUCHID_REASON is set to pass the reason string.
func runJXAScript(script string, reason string) (string, error) {
	dir, err := os.MkdirTemp("", "apm-touchid-*")
	if err != nil {
		return "", fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	scriptPath := filepath.Join(dir, "script.js")
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return "", fmt.Errorf("write script: %w", err)
	}

	cmd := exec.Command("osascript", "-l", "JavaScript", scriptPath)
	cmd.Env = append(os.Environ(), touchIDReasonEnv+"="+reason)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("osascript exited: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// authenticateWithTouchID prompts for Touch ID and returns true on success.
func authenticateWithTouchID(reason string) (bool, error) {
	out, err := runJXAScript(authScriptTemplate, reason)
	if err != nil {
		return false, err
	}

	if out == "true" {
		return true, nil
	}

	if strings.HasPrefix(out, "false:") {
		errMsg := strings.TrimPrefix(out, "false:")
		if errMsg == "" || strings.Contains(strings.ToLower(errMsg), "cancel") {
			return false, ErrAuthFailed
		}
		return false, fmt.Errorf("touch id: %s", errMsg)
	}

	return false, fmt.Errorf("unexpected osascript output: %s", out)
}

// IsAvailable checks whether Touch ID hardware is present on this Mac.
func IsAvailable() bool {
	out, err := runJXAScript(availableScript, "")
	return err == nil && out == "true"
}

// IsConfigured checks whether the vault master password is stored in the
// login keychain under the expected service/account name.
func IsConfigured() bool {
	cmd := exec.Command("security", "find-generic-password",
		"-s", KeychainService,
		"-a", KeychainAccount,
		"-w",
	)
	return cmd.Run() == nil
}

// Setup stores the master password in the macOS login keychain.
func Setup(masterPassword string) error {
	ok, err := authenticateWithTouchID("Set up Touch ID for APM")
	if err != nil {
		return err
	}
	if !ok {
		return ErrAuthFailed
	}
	return Store(masterPassword)
}

// Store writes the master password to the login keychain without a Touch ID
// prompt. The desktop app calls it once the master password is confirmed.
func Store(masterPassword string) error {
	cmd := exec.Command("security", "add-generic-password",
		"-s", KeychainService,
		"-a", KeychainAccount,
		"-w", masterPassword,
		"-U",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain write failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// GetPassword retrieves the master password from the login keychain.
func GetPassword() (string, error) {
	ok, err := authenticateWithTouchID("Unlock APM vault")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrAuthFailed
	}
	return ReadPassword()
}

// ReadPassword reads the master password from the login keychain without a
// Touch ID prompt. The desktop app calls it after checking the fingerprint
// itself.
func ReadPassword() (string, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-s", KeychainService,
		"-a", KeychainAccount,
		"-w",
	)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("keychain read failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Remove deletes the stored master password from the login keychain.
func Remove() error {
	ok, err := authenticateWithTouchID("Remove Touch ID from APM")
	if err != nil {
		return err
	}
	if !ok {
		return ErrAuthFailed
	}
	return Delete()
}

// Delete removes the stored master password from the login keychain without
// a Touch ID prompt.
func Delete() error {
	cmd := exec.Command("security", "delete-generic-password",
		"-s", KeychainService,
		"-a", KeychainAccount,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain delete failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Status returns a JSON-serialisable status map.
func Status() map[string]interface{} {
	available := IsAvailable()
	configured := IsConfigured()
	return map[string]interface{}{
		"available":  available,
		"configured": configured,
		"platform":   "darwin",
	}
}

// StatusText returns a human-readable status string.
func StatusText() string {
	status := Status()
	available := status["available"].(bool)
	configured := status["configured"].(bool)

	if !available {
		return "Touch ID is not available on this Mac"
	}
	if !configured {
		return "Touch ID is available but not configured. Run 'pm auth touchid setup'."
	}
	return "Touch ID is configured and ready"
}

// Authenticate prompts the user for Touch ID and returns nil on success.
func Authenticate(reason string) error {
	ok, err := authenticateWithTouchID(reason)
	if err != nil {
		return err
	}
	if !ok {
		return ErrAuthFailed
	}
	return nil
}
