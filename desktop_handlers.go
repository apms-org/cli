package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	src "github.com/aaravmaloo/apm/src"
	"github.com/aaravmaloo/apm/src/touchid"
)

var desktopMethods map[string]desktopMethod

func init() {
	desktopMethods = map[string]desktopMethod{
		"app.hello":                 {fn: hAppHello},
		"vault.status":              {fn: hVaultStatus},
		"vault.unlock":              {fn: hVaultUnlock},
		"vault.unlockTouchID":       {fn: hVaultUnlockTouchID, long: true},
		"touchid.reply":             {fn: hTouchIDReply, long: true},
		"vault.unlockSession":       {fn: hVaultUnlockSession},
		"vault.lock":                {fn: hVaultLock},
		"vault.readonly":            {fn: hVaultReadonly},
		"vault.setup":               {fn: hVaultSetup},
		"vault.snapshot":            {fn: hVaultSnapshot},
		"vault.destroy":             {fn: hVaultDestroy},
		"vault.meta":                {fn: hVaultMeta},
		"vault.settings":            {fn: hVaultSettings},
		"vault.backup":              {fn: hVaultBackup},
		"item.add":                  {fn: hItemAdd},
		"item.update":               {fn: hItemUpdate},
		"item.meta":                 {fn: hItemMeta},
		"item.used":                 {fn: hItemUsed},
		"item.duplicate":            {fn: hItemDuplicate},
		"item.delete":               {fn: hItemDelete},
		"item.restore":              {fn: hItemRestore},
		"item.purge":                {fn: hItemPurge},
		"trash.empty":               {fn: hTrashEmpty},
		"item.move":                 {fn: hItemMove},
		"item.favorite":             {fn: hItemFavorite},
		"item.restoreVersion":       {fn: hItemRestoreVersion},
		"item.useCode":              {fn: hItemUseCode},
		"item.file":                 {fn: hItemFile},
		"item.saveFile":             {fn: hItemSaveFile},
		"item.import":               {fn: hItemImport},
		"totp.order":                {fn: hTOTPOrder},
		"passkey.remove":            {fn: hPasskeyRemove},
		"passkey.rename":            {fn: hPasskeyRename},
		"space.add":                 {fn: hSpaceAdd},
		"space.rename":              {fn: hSpaceRename},
		"space.delete":              {fn: hSpaceDelete},
		"space.color":               {fn: hSpaceColor},
		"security.changePassword":   {fn: hChangePassword},
		"security.profile":          {fn: hSecurityProfile},
		"security.touchId":          {fn: hSecurityTouchID, long: true},
		"policy.load":               {fn: hPolicyLoad},
		"policy.clear":              {fn: hPolicyClear},
		"recovery.email.start":      {fn: hRecoveryEmailStart, long: true},
		"recovery.email.verify":     {fn: hRecoveryEmailVerify, long: true},
		"recovery.key.create":       {fn: hRecoveryKeyCreate},
		"recovery.codes.generate":   {fn: hRecoveryCodesGenerate},
		"recovery.passkey.register": {fn: hRecoveryPasskeyRegister, long: true},
		"recovery.passkey.remove":   {fn: hRecoveryPasskeyRemove},
		"recovery.quorum.setup":     {fn: hRecoveryQuorumSetup},
		"recovery.reset":            {fn: hRecoveryReset},
		"recover.start":             {fn: hRecoverStart},
		"recover.email.send":        {fn: hRecoverEmailSend, long: true},
		"recover.email.verify":      {fn: hRecoverEmailVerify},
		"recover.verify":            {fn: hRecoverVerify, long: true},
		"recover.reset":             {fn: hRecoverReset, long: true},
		"lgit.undo":                 {fn: hLGitUndo},
		"lgit.checkout":             {fn: hLGitCheckout},
		"lgit.squash":               {fn: hLGitSquash},
		"lgit.prune":                {fn: hLGitPrune},
		"lgit.verify":               {fn: hLGitVerify},
		"sessions.issue":            {fn: hSessionsIssue},
		"sessions.revoke":           {fn: hSessionsRevoke},
		"sync.connect":              {fn: hSyncConnect, long: true},
		"sync.disconnect":           {fn: hSyncDisconnect},
		"sync.now":                  {fn: hSyncNow, long: true},
		"sync.diff":                 {fn: hSyncDiff, long: true},
		"sync.apply":                {fn: hSyncApply, long: true},
		"sync.ignore":               {fn: hSyncIgnore},
		"sync.auto":                 {fn: hSyncAuto},
		"sync.restore":              {fn: hSyncRestore, long: true},
		"mcp.enabled":               {fn: hMCPEnabled},
		"mcp.client":                {fn: hMCPClient},
		"mcp.token.create":          {fn: hMCPTokenCreate},
		"mcp.token.revoke":          {fn: hMCPTokenRevoke},
		"mcp.tx.approve":            {fn: hMCPTxApprove},
		"mcp.tx.abort":              {fn: hMCPTxAbort},
		"mcp.config":                {fn: hMCPConfig},
		"data.export":               {fn: hDataExport},
		"data.import":               {fn: hDataImport},
		"transfer.formats":          {fn: hTransferFormats},
		"transfer.preview":          {fn: hTransferPreview, long: true},
		"transfer.compare":          {fn: hTransferCompare, long: true},
		"transfer.plan":             {fn: hTransferPlan},
		"transfer.apply":            {fn: hTransferApply},
		"transfer.discard":          {fn: hTransferDiscard},
		"transfer.exportPreview":    {fn: hTransferExportPreview},
		"transfer.export":           {fn: hTransferExport, long: true},
		"cleanup.scan":              {fn: hCleanupScan},
		"cleanup.apply":             {fn: hCleanupApply},
		"audit.log":                 {fn: hAuditLog},
		"inject.preview":            {fn: hInjectPreview},
		"bridge.info":               {fn: hBridgeInfo},
		"bridge.rotate":             {fn: hBridgeRotate},
		"bridge.pairRespond":        {fn: hBridgePairRespond},
		"icons.get":                 {fn: hIconsGet},
		"icons.clear":               {fn: hIconsClear},
	}
}

func hAppHello(s *desktopServer, p json.RawMessage) (any, error) {
	return map[string]any{"version": Version, "backend": "pm desktop", "vaultPath": s.vaultPath, "platform": runtime.GOOS, "pid": os.Getpid()}, nil
}

func headerRecoveryView(rec src.RecoveryData, ok bool) map[string]any {
	if !ok {
		return map[string]any{"email": "", "emailSet": false, "key": false, "codes": map[string]any{"total": 0, "unused": 0}, "passkey": false, "quorum": nil}
	}
	email := rec.EmailHint
	if email == "" && len(rec.EmailHash) > 0 {
		email = "•••"
	}
	unused := 0
	for i := range rec.RecoveryCodeHashes {
		if i >= len(rec.RecoveryCodeUsed) || !rec.RecoveryCodeUsed[i] {
			unused++
		}
	}
	var quorum any
	if rec.RecoveryShareThreshold >= 2 && len(rec.RecoveryShareHashes) > 0 {
		quorum = map[string]any{"threshold": rec.RecoveryShareThreshold, "shares": rec.RecoveryShareCount}
	}
	return map[string]any{
		"email":    email,
		"emailSet": len(rec.EmailHash) > 0,
		"key":      len(rec.KeyHash) > 0 && len(rec.DEKSlot) > 0,
		"codes":    map[string]any{"total": len(rec.RecoveryCodeHashes), "unused": unused},
		"passkey":  rec.RecoveryPasskeyEnabled && len(rec.RecoveryPasskeyCred) > 0,
		"quorum":   quorum,
	}
}

func hVaultStatus(s *desktopServer, p json.RawMessage) (any, error) {
	exists := src.VaultExists(s.vaultPath)
	res := map[string]any{
		"exists":     exists,
		"unlocked":   s.unlocked(),
		"readonly":   s.unlocked() && s.isReadonly(),
		"path":       s.vaultPath,
		"touchId":    map[string]any{"available": s.touchIDAvailable(), "configured": s.touchIDConfigured()},
		"cliSession": false,
		"failures":   src.GetFailureCount(),
		"cooldown":   0,
		"recovery":   headerRecoveryView(src.RecoveryData{}, false),
		"profile":    nil,
		"size":       int64(0),
		"modified":   int64(0),
	}
	if wait := time.Until(s.cooldownUntil); wait > 0 {
		res["cooldown"] = int((wait + time.Second - 1) / time.Second)
	}
	// The revision lives inside the encrypted payload, so it is only known
	// once the vault is unlocked; while locked newerFormat stays false.
	s.formatView(res)
	if !exists {
		return res, nil
	}
	if sess, err := src.PeekSession(); err == nil && sess != nil {
		res["cliSession"] = true
	}
	if st, err := os.Stat(s.vaultPath); err == nil {
		res["size"] = st.Size()
		res["modified"] = ms(st.ModTime())
	}
	data, err := src.LoadVault(s.vaultPath)
	if err == nil {
		if prof, _, perr := src.GetVaultParams(data); perr == nil {
			res["profile"] = profileView(prof)
		}
		rec, ok := src.ParseVaultHeaderRecovery(data)
		res["recovery"] = headerRecoveryView(rec, ok)
	}
	return res, nil
}

func (s *desktopServer) finishUnlock(password string, v *src.Vault, via string, createSession bool) map[string]any {
	src.LogAccess("UNLOCK")
	alerts := src.CheckAnomalies(nil)
	v.FailedAttempts = 0
	v.EmergencyMode = false
	src.ClearFailures()
	s.wrongStreak = 0
	s.cooldownUntil = time.Time{}
	if v.AlertsEnabled && v.AnomalyDetectionEnabled && len(alerts) > 0 {
		src.SendAlert(v, src.LevelCritical, "ANOMALY", fmt.Sprintf("Unusual activity detected during unlock: %v", alerts))
	}
	s.vault = v
	s.password = password
	s.rec = nil
	// A vault from a newer pm opens read-only and is never repaired here.
	if v.NeedsRepair && !v.IsNewerFormat() {
		_ = s.save("Repaired vault format")
	}
	if data, err := os.ReadFile(s.vaultPath); err == nil {
		s.lastWriteHash = sha256Hex(data)
	}
	if createSession {
		_ = lockPolicyOf(v).startSession(password, false)
	}
	details := "Desktop unlock"
	if via != "" {
		details += " via " + via
	}
	src.LogAction("VAULT_UNLOCKED", details)
	if len(alerts) > 0 {
		src.LogAction("ANOMALY", strings.Join(alerts, "; "))
	}
	s.markKnownTx()
	return map[string]any{"ok": true, "snapshot": s.snapshot()}
}

func (s *desktopServer) guardAttempt() error {
	if !src.VaultExists(s.vaultPath) {
		return rpcErr("no_vault", "No vault found at "+s.vaultPath+".")
	}
	if wait := time.Until(s.cooldownUntil); wait > 0 {
		secs := int((wait + time.Second - 1) / time.Second)
		return rpcErrData("cooldown", fmt.Sprintf("Too many attempts. Try again in %d seconds.", secs), map[string]any{"wait": secs})
	}
	if src.GetFailureCount() >= 6 {
		return rpcErr("breach_lock", "This vault is locked after repeated failed attempts. Use recovery to regain access.")
	}
	return nil
}

func (s *desktopServer) registerFailure(data []byte) error {
	src.LogAccess("FAIL")
	src.TrackFailure()
	src.LogAction("UNLOCK_FAILED", "Incorrect master password")
	if rec, err := src.GetVaultRecoveryInfo(data); err == nil && rec.AlertsEnabled && rec.AlertEmail != "" {
		src.SendAlert(&src.Vault{AlertEmail: rec.AlertEmail, AlertsEnabled: rec.AlertsEnabled, SecurityLevel: rec.SecurityLevel}, src.LevelCritical, "BREACH ATTEMPT", "Failed desktop unlock attempt detected.")
	}
	failures := src.GetFailureCount()
	left := 6 - failures
	if left <= 0 {
		return rpcErrData("breach_lock", "This vault is locked after repeated failed attempts. Use recovery to regain access.", map[string]any{"left": 0})
	}
	s.wrongStreak++
	if s.wrongStreak%3 == 0 {
		s.cooldownUntil = time.Now().Add(30 * time.Second)
		return rpcErrData("cooldown", "Too many attempts. Try again in 30 seconds.", map[string]any{"wait": 30, "left": left})
	}
	return rpcErrData("wrong_password", "That master password is not correct.", map[string]any{"left": left})
}

func hVaultUnlock(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.guardAttempt(); err != nil {
		return nil, err
	}
	data, err := src.LoadVault(s.vaultPath)
	if err != nil {
		return nil, err
	}
	v, derr := src.DecryptVault(data, in.Password, 1)
	if derr != nil {
		return nil, s.registerFailure(data)
	}
	return s.finishUnlock(in.Password, v, "password", true), nil
}

func hVaultUnlockTouchID(s *desktopServer, p json.RawMessage) (any, error) {
	return s.unlockWithTouchID("unlock your vault", true)
}

// unlockWithTouchID checks the fingerprint, then opens the vault with the
// master password kept in the Keychain. inline runs the check on the app's
// lock screen instead of a system dialog.
func (s *desktopServer) unlockWithTouchID(reason string, inline bool) (any, error) {
	s.mu.Lock()
	if err := s.guardAttempt(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	avail := s.touchIDAvailable()
	conf := s.touchIDConfigured()
	s.mu.Unlock()
	if !avail {
		return nil, rpcErr("touchid_unavailable", "Touch ID is not available on this Mac.")
	}
	if !conf {
		return nil, rpcErr("touchid_unavailable", "Touch ID is not set up for APM.")
	}
	if err := s.verifyTouchID(reason, inline); err != nil {
		return nil, err
	}
	pass, err := touchid.ReadPassword()
	if err != nil {
		return nil, rpcErr("touchid_failed", "Touch ID failed: "+err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := src.LoadVault(s.vaultPath)
	if err != nil {
		return nil, err
	}
	v, derr := src.DecryptVault(data, pass, 1)
	if derr != nil {
		return nil, rpcErrData("wrong_password", "Touch ID has an outdated master password. Unlock with your password, then set Touch ID up again.", map[string]any{"stale": true})
	}
	return s.finishUnlock(pass, v, "Touch ID", true), nil
}

func hVaultUnlockSession(s *desktopServer, p json.RawMessage) (any, error) {
	if !src.VaultExists(s.vaultPath) {
		return nil, rpcErr("no_vault", "No vault found at "+s.vaultPath+".")
	}
	sess, err := src.GetSession()
	if err != nil || sess == nil {
		return nil, rpcErr("locked", "There is no active CLI session.")
	}
	if sess.ReadOnly && src.GetFailureCount() >= 6 {
		return nil, rpcErr("breach_lock", "This vault is locked after repeated failed attempts. Use recovery to regain access.")
	}
	data, err := src.LoadVault(s.vaultPath)
	if err != nil {
		return nil, err
	}
	v, derr := src.DecryptVault(data, sess.MasterPassword, 1)
	if derr != nil {
		_ = src.KillSession()
		return nil, rpcErr("locked", "The CLI session no longer matches this vault.")
	}
	res := s.finishUnlock(sess.MasterPassword, v, "CLI session", false)
	if sess.ReadOnly {
		s.readonlyUntil = sess.Expiry
		if s.readonlyUntil.IsZero() {
			s.readonlyUntil = time.Now().AddDate(1, 0, 0)
		}
		res["snapshot"] = s.snapshot()
	}
	return res, nil
}

func hVaultLock(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Reason string `json:"reason"`
	}
	_ = decodeParams(p, &in)
	was := s.unlocked()
	s.dropKey()
	s.rec = nil
	_ = src.KillSession()
	if was {
		reason := strings.TrimSpace(in.Reason)
		if reason == "" {
			reason = "Desktop lock"
		}
		src.LogAction("VAULT_LOCKED", reason)
	}
	return map[string]any{"ok": true}, nil
}

func hVaultReadonly(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Minutes int `json:"minutes"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	if in.Minutes <= 0 {
		s.readonlyUntil = time.Time{}
		src.LogAction("READONLY_ENDED", "Read-only mode ended")
	} else {
		s.readonlyUntil = time.Now().Add(time.Duration(in.Minutes) * time.Minute)
		src.LogAction("READONLY_SESSION", fmt.Sprintf("%d minutes", in.Minutes))
	}
	return s.withSnapshot(map[string]any{"until": ms(s.readonlyUntil)}), nil
}

func hVaultSetup(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Password   string               `json:"password"`
		Name       string               `json:"name"`
		Profile    string               `json:"profile"`
		Custom     *customProfileParams `json:"custom"`
		Cipher     string               `json:"cipher"`
		Spaces     []string             `json:"spaces"`
		TouchID    bool                 `json:"touchId"`
		Alerts     bool                 `json:"alerts"`
		AlertEmail string               `json:"alertEmail"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	result, err := func() (map[string]any, error) {
		if src.VaultExists(s.vaultPath) {
			return nil, rpcErr("vault_exists", "A vault already exists at "+s.vaultPath+".")
		}
		if err := src.ValidateMasterPassword(in.Password); err != nil {
			return nil, rpcErr("invalid", err.Error())
		}
		params, profileName, err := buildCryptoProfile(in.Profile, in.Custom, in.Cipher)
		if err != nil {
			return nil, err
		}
		dir := filepath.Dir(s.vaultPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		_ = os.MkdirAll(filepath.Join(dir, "policies"), 0750)
		now := time.Now()
		v := &src.Vault{
			Profile:              profileName,
			CurrentProfileParams: &params,
			Spaces:               []string{"default"},
			SecurityLevel:        1,
			Desktop:              &src.DesktopState{Name: strings.TrimSpace(in.Name), Created: now, SpaceCreated: map[string]time.Time{}, SpaceColors: map[string]int{}},
		}
		for _, sp := range in.Spaces {
			sp = strings.TrimSpace(sp)
			if sp == "" || strings.EqualFold(sp, "default") {
				continue
			}
			dup := false
			for _, e := range v.Spaces {
				if strings.EqualFold(e, sp) {
					dup = true
				}
			}
			if dup {
				continue
			}
			v.Desktop.SpaceColors[sp] = (len(v.Spaces) - 1) % 7
			v.Spaces = append(v.Spaces, sp)
			v.Desktop.SpaceCreated[sp] = now
		}
		if in.Alerts {
			v.AlertsEnabled = true
			v.AnomalyDetectionEnabled = true
			v.AlertEmail = strings.TrimSpace(in.AlertEmail)
		}
		data, err := src.EncryptVault(v, in.Password)
		if err != nil {
			return nil, err
		}
		if err := s.writeVault(data, true, "Vault created"); err != nil {
			return nil, err
		}
		src.LogAction("SETUP_COMPLETED", "Desktop setup, profile "+profileName)
		return s.finishUnlock(in.Password, v, "setup", true), nil
	}()
	if err != nil {
		return nil, err
	}
	if in.TouchID {
		if !s.touchIDAvailable() {
			result["touchIdError"] = "Touch ID is not available on this Mac."
		} else if terr := storeTouchID(in.Password); terr != nil {
			result["touchIdError"] = terr.Error()
		} else {
			s.touchConf = 1
			src.LogAction("TOUCHID_ENABLED", "Configured during setup")
			result["snapshot"] = s.snapshot()
		}
	}
	return result, nil
}

func hVaultSnapshot(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	return s.snapshot(), nil
}

func hVaultDestroy(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	c := strings.TrimSpace(in.Confirm)
	if !strings.EqualFold(c, s.vaultName()) && c != "DESTROY" {
		return nil, rpcErr("invalid", "Type the vault name to confirm.")
	}
	if f, err := os.OpenFile(s.vaultPath, os.O_WRONLY, 0); err == nil {
		if st, serr := f.Stat(); serr == nil {
			junk := make([]byte, st.Size())
			_, _ = rand.Read(junk)
			_, _ = f.WriteAt(junk, 0)
		}
		f.Close()
	}
	s.lastWriteHash = ""
	if err := os.Remove(s.vaultPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	removed, _ := src.PurgeLGitForVault(s.vaultPath)
	if list, err := src.ListEphemeralSessions(); err == nil {
		for _, e := range list {
			if !e.Revoked {
				_, _ = src.RevokeEphemeralSession(e.ID)
			}
		}
	}
	_ = src.KillSession()
	s.dropKey()
	src.LogAction("VAULT_DESTROYED", fmt.Sprintf("Vault permanently deleted from the desktop app, %d history snapshots removed", removed))
	return map[string]any{"ok": true, "historyRemoved": removed}, nil
}

func hVaultMeta(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Name          *string `json:"name"`
		Alerts        *bool   `json:"alerts"`
		AlertEmail    *string `json:"alertEmail"`
		SecurityLevel *int    `json:"securityLevel"`
		Anomaly       *bool   `json:"anomaly"`
		ActiveSpace   *string `json:"activeSpace"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	v := s.vault
	var changed []string
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" {
			return nil, rpcErr("invalid", "Give the vault a name.")
		}
		s.desktop().Name = n
		changed = append(changed, "name")
	}
	if in.AlertEmail != nil {
		v.AlertEmail = strings.TrimSpace(*in.AlertEmail)
		changed = append(changed, "alert email")
	}
	if in.Alerts != nil {
		v.AlertsEnabled = *in.Alerts
		changed = append(changed, "alerts")
	}
	if in.SecurityLevel != nil {
		if *in.SecurityLevel < 1 || *in.SecurityLevel > 3 {
			return nil, rpcErr("invalid", "Security level must be 1, 2 or 3.")
		}
		v.SecurityLevel = *in.SecurityLevel
		changed = append(changed, "security level")
	}
	if in.Anomaly != nil {
		v.AnomalyDetectionEnabled = *in.Anomaly
		changed = append(changed, "anomaly detection")
	}
	if in.ActiveSpace != nil {
		sp := normalizeSpaceParam(*in.ActiveSpace)
		if sp != "" {
			existing, ok := s.spaceExists(sp)
			if !ok {
				return nil, rpcErr("not_found", "Space "+sp+" does not exist.")
			}
			sp = existing
		}
		v.CurrentSpace = sp
		changed = append(changed, "active space")
	}
	if len(changed) == 0 {
		return s.withSnapshot(nil), nil
	}
	if err := s.save("Settings changed: " + strings.Join(changed, ", ")); err != nil {
		return nil, err
	}
	src.LogAction("SETTINGS_CHANGED", strings.Join(changed, ", "))
	if in.Alerts != nil {
		status := "OFF"
		if v.AlertsEnabled {
			status = "ON"
		}
		src.SendAlert(v, src.LevelSettings, "ALERT SETTINGS", "Global security alerts turned "+status+".")
	}
	if in.SecurityLevel != nil {
		src.SendAlert(v, src.LevelSettings, "SECURITY LEVEL", fmt.Sprintf("Security paranoia level updated to %d.", v.SecurityLevel))
	}
	return s.withSnapshot(nil), nil
}

func hVaultSettings(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Patch map[string]any `json:"patch"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if len(in.Patch) == 0 {
		return s.withSnapshot(nil), nil
	}
	d := s.desktop()
	if d.Settings == nil {
		d.Settings = map[string]any{}
	}
	keys := make([]string, 0, len(in.Patch))
	for k, val := range in.Patch {
		d.Settings[k] = val
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if err := s.save("Settings changed"); err != nil {
		return nil, err
	}
	src.LogAction("SETTINGS_CHANGED", strings.Join(keys, ", "))
	return s.withSnapshot(nil), nil
}

func hVaultBackup(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Path string `json:"path"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Path) == "" {
		return nil, rpcErr("invalid", "Choose where to save the backup.")
	}
	data, err := os.ReadFile(s.vaultPath)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(in.Path, data, 0600); err != nil {
		return nil, err
	}
	src.LogAction("BACKUP_CREATED", "Encrypted vault copied to "+in.Path)
	return map[string]any{"ok": true, "bytes": len(data)}, nil
}

func (s *desktopServer) checkPolicy(typeID string, f map[string]any) error {
	pol := s.vault.ActivePolicy
	if pol.Name == "" || (typeID != "password" && typeID != "wifi") {
		return nil
	}
	pw, ok := f["password"]
	if !ok {
		return nil
	}
	if err := pol.PasswordPolicy.Validate(toStr(pw)); err != nil {
		return rpcErr("invalid", "Policy "+pol.Name+": "+err.Error())
	}
	return nil
}

func hItemAdd(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Type  string         `json:"type"`
		Space string         `json:"space"`
		F     map[string]any `json:"f"`
		Fav   bool           `json:"fav"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if in.F == nil {
		in.F = map[string]any{}
	}
	if err := s.checkPolicy(in.Type, in.F); err != nil {
		return nil, err
	}
	space := s.ensureSpace(normalizeSpaceParam(in.Space))
	ref, err := s.vault.AddItem(in.Type, space, in.F)
	if err != nil {
		if errors.Is(err, src.ErrItemExists) {
			return nil, rpcErr("exists", "An item called "+strings.TrimSpace(toStr(in.F[titleKeyFor(in.Type)]))+" already exists in this space.")
		}
		return nil, err
	}
	if in.Fav {
		s.setFavorite(ref.ID, true)
	}
	if err := s.save("Added " + ref.Title); err != nil {
		return nil, err
	}
	src.LogAction("VAULT_SAVED", "Added "+ref.Title)
	item, _ := s.itemByID(ref.ID)
	return s.withSnapshot(map[string]any{"item": item}), nil
}

func titleKeyFor(typeID string) string {
	if spec, ok := src.ItemTypeByID(typeID); ok {
		return spec.TitleKey
	}
	return "name"
}

func (s *desktopServer) pushVersion(id string, f map[string]any) {
	d := s.desktop()
	if d.Versions == nil {
		d.Versions = map[string][]src.ItemVersion{}
	}
	list := append([]src.ItemVersion{{F: f, TS: time.Now()}}, d.Versions[id]...)
	if len(list) > 20 {
		list = list[:20]
	}
	d.Versions[id] = list
}

func (s *desktopServer) updateItem(id string, f map[string]any, space *string, versioned bool) (src.VaultItemRef, error) {
	ref, ok := s.vault.FindItem(id)
	if !ok {
		return src.VaultItemRef{}, rpcErr("not_found", "That item no longer exists.")
	}
	if f == nil {
		f = map[string]any{}
	}
	if err := s.checkPolicy(ref.Spec.ID, f); err != nil {
		return src.VaultItemRef{}, err
	}
	before := s.vault.ItemRefs()
	newRef, prev, err := s.vault.UpdateItem(id, f, space)
	if err != nil {
		if errors.Is(err, src.ErrItemExists) {
			return src.VaultItemRef{}, rpcErr("exists", "Another item with that name already exists in that space.")
		}
		return src.VaultItemRef{}, err
	}
	s.remapByIndex(before, "", -1)
	s.renameID(id, newRef.ID)
	if versioned {
		changed := false
		now := s.vault.ItemRecordFields(newRef)
		for k, v := range prev {
			if k == "file" {
				continue
			}
			a, _ := json.Marshal(v)
			b, _ := json.Marshal(now[k])
			if string(a) != string(b) {
				changed = true
				break
			}
		}
		if changed {
			s.pushVersion(newRef.ID, prev)
		}
	}
	return newRef, nil
}

func hItemUpdate(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID    string         `json:"id"`
		F     map[string]any `json:"f"`
		Space *string        `json:"space"`
		Note  string         `json:"note"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	var space *string
	if in.Space != nil {
		sp := s.ensureSpace(normalizeSpaceParam(*in.Space))
		space = &sp
	}
	ref, err := s.updateItem(in.ID, in.F, space, true)
	if err != nil {
		return nil, err
	}
	note := strings.TrimSpace(in.Note)
	if note == "" {
		note = "Edited " + ref.Title
	}
	if err := s.save(note); err != nil {
		return nil, err
	}
	src.LogAction("VAULT_SAVED", note)
	item, _ := s.itemByID(ref.ID)
	return s.withSnapshot(map[string]any{"item": item, "id": ref.ID}), nil
}

func hItemMeta(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID        string  `json:"id"`
		Privilege *string `json:"privilege"`
		Exposed   *bool   `json:"exposed"`
		Fav       *bool   `json:"fav"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	ref, ok := s.vault.FindItem(in.ID)
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	if in.Privilege != nil || in.Exposed != nil {
		s.vault.SetItemTelemetryFlags(ref, in.Privilege, in.Exposed)
	}
	if in.Fav != nil {
		s.setFavorite(ref.ID, *in.Fav)
	}
	if err := s.save("Updated " + ref.Title); err != nil {
		return nil, err
	}
	item, _ := s.itemByID(ref.ID)
	return s.withSnapshot(map[string]any{"item": item}), nil
}

func hItemUsed(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	ref, ok := s.vault.FindItem(in.ID)
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	s.vault.RecordItemAccess(ref)
	if !s.isReadonly() {
		if err := s.saveQuiet(); err != nil {
			return nil, err
		}
	}
	return s.withSnapshot(nil), nil
}

func hItemDuplicate(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	ref, ok := s.vault.FindItem(in.ID)
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	f := s.vault.ItemRecordFields(ref)
	if ref.Spec.Media {
		name, content, _ := s.vault.ItemFileContent(ref)
		f["file"] = map[string]any{"name": name, "data": base64.StdEncoding.EncodeToString(content)}
	}
	base := ref.Title + " copy"
	title := base
	for n := 2; ; n++ {
		probe := map[string]any{}
		for k, v := range f {
			probe[k] = v
		}
		probe[ref.Spec.TitleKey] = title
		newRef, err := s.vault.AddItem(ref.Spec.ID, ref.Space, probe)
		if err == nil {
			if err := s.save("Duplicated " + ref.Title); err != nil {
				return nil, err
			}
			src.LogAction("VAULT_SAVED", "Duplicated "+ref.Title)
			item, _ := s.itemByID(newRef.ID)
			return s.withSnapshot(map[string]any{"item": item}), nil
		}
		if !errors.Is(err, src.ErrItemExists) || n > 50 {
			return nil, err
		}
		title = fmt.Sprintf("%s %d", base, n)
	}
}

func (s *desktopServer) trashItem(id string) (src.TrashedItem, error) {
	ref, ok := s.vault.FindItem(id)
	if !ok {
		return src.TrashedItem{}, rpcErr("not_found", "That item no longer exists.")
	}
	fav := s.isFavorite(id)
	before := s.vault.ItemRefs()
	t, err := s.vault.RemoveItem(id)
	if err != nil {
		return t, err
	}
	t.Favorite = fav
	s.setFavorite(id, false)
	d := s.desktop()
	if d.Versions != nil {
		if list, ok := d.Versions[id]; ok {
			d.Versions[t.ID] = list
			delete(d.Versions, id)
		}
	}
	s.remapByIndex(before, ref.Spec.ID, ref.Index)
	d.Trash = append([]src.TrashedItem{t}, d.Trash...)
	return t, nil
}

func hItemDelete(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	var titles []string
	var trashIDs []string
	for _, id := range in.IDs {
		t, err := s.trashItem(id)
		if err != nil {
			var re *rpcError
			if errors.As(err, &re) && re.Code == "not_found" {
				continue
			}
			return nil, err
		}
		titles = append(titles, t.Title)
		trashIDs = append(trashIDs, t.ID)
	}
	if len(titles) == 0 {
		return nil, rpcErr("not_found", "Those items no longer exist.")
	}
	note := "Deleted " + titles[0]
	if len(titles) > 1 {
		note = fmt.Sprintf("Deleted %d items", len(titles))
	}
	if err := s.save(note); err != nil {
		return nil, err
	}
	src.LogAction("VAULT_SAVED", note)
	return s.withSnapshot(map[string]any{"deleted": len(titles), "trashIds": trashIDs}), nil
}

func (s *desktopServer) findTrash(id string) (int, bool) {
	if s.vault.Desktop == nil {
		return -1, false
	}
	for i, t := range s.vault.Desktop.Trash {
		if t.ID == id {
			return i, true
		}
	}
	return -1, false
}

func hItemRestore(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	restored := []string{}
	var titles []string
	conflicts := []string{}
	for _, id := range in.IDs {
		i, ok := s.findTrash(id)
		if !ok {
			continue
		}
		d := s.vault.Desktop
		t := d.Trash[i]
		ref, err := s.vault.RestoreTrashedItem(t)
		if err != nil {
			if errors.Is(err, src.ErrItemExists) {
				conflicts = append(conflicts, t.Title)
				continue
			}
			return nil, err
		}
		d.Trash = append(d.Trash[:i], d.Trash[i+1:]...)
		if d.Versions != nil {
			if list, ok := d.Versions[t.ID]; ok {
				d.Versions[ref.ID] = list
				delete(d.Versions, t.ID)
			}
		}
		if t.Favorite {
			s.setFavorite(ref.ID, true)
		}
		restored = append(restored, ref.ID)
		titles = append(titles, ref.Title)
	}
	if len(restored) == 0 {
		if len(conflicts) > 0 {
			return nil, rpcErrData("exists", "An item with the same name already exists: "+strings.Join(conflicts, ", ")+".", map[string]any{"conflicts": conflicts})
		}
		return nil, rpcErr("not_found", "Those items are no longer in the trash.")
	}
	note := "Restored " + titles[0]
	if len(titles) > 1 {
		note = fmt.Sprintf("Restored %d items", len(titles))
	}
	if err := s.save(note); err != nil {
		return nil, err
	}
	src.LogAction("VAULT_SAVED", note)
	return s.withSnapshot(map[string]any{"restored": restored, "conflicts": conflicts}), nil
}

func (s *desktopServer) purgeTrash(ids map[string]bool, all bool) int {
	d := s.desktop()
	kept := d.Trash[:0:0]
	n := 0
	for _, t := range d.Trash {
		if all || ids[t.ID] {
			n++
			if d.Versions != nil {
				delete(d.Versions, t.ID)
			}
			continue
		}
		kept = append(kept, t)
	}
	d.Trash = kept
	return n
}

func hItemPurge(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, id := range in.IDs {
		set[id] = true
	}
	n := s.purgeTrash(set, false)
	if n == 0 {
		return s.withSnapshot(map[string]any{"purged": 0}), nil
	}
	if err := s.save(fmt.Sprintf("Deleted %d item(s) permanently", n)); err != nil {
		return nil, err
	}
	src.LogAction("ENTRY_PURGED", fmt.Sprintf("%d item(s) deleted permanently", n))
	return s.withSnapshot(map[string]any{"purged": n}), nil
}

func hTrashEmpty(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	n := s.purgeTrash(nil, true)
	if n > 0 {
		if err := s.save(fmt.Sprintf("Emptied trash (%d)", n)); err != nil {
			return nil, err
		}
		src.LogAction("TRASH_EMPTIED", fmt.Sprintf("%d item(s)", n))
	}
	return s.withSnapshot(map[string]any{"purged": n}), nil
}

func hItemMove(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs   []string `json:"ids"`
		Space string   `json:"space"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	target := s.ensureSpace(normalizeSpaceParam(in.Space))
	moved := map[string]string{}
	conflicts := []string{}
	for _, id := range in.IDs {
		ref, ok := s.vault.FindItem(id)
		if !ok {
			continue
		}
		newRef, err := s.updateItem(id, nil, &target, false)
		if err != nil {
			var re *rpcError
			if errors.As(err, &re) && re.Code == "exists" {
				conflicts = append(conflicts, ref.Title)
				continue
			}
			return nil, err
		}
		moved[id] = newRef.ID
	}
	if len(moved) == 0 {
		if len(conflicts) > 0 {
			return nil, rpcErrData("exists", "Items with the same name already exist there: "+strings.Join(conflicts, ", ")+".", map[string]any{"conflicts": conflicts})
		}
		return nil, rpcErr("not_found", "Those items no longer exist.")
	}
	label := target
	if label == "" {
		label = "Default"
	}
	note := fmt.Sprintf("Moved %d item(s) to %s", len(moved), label)
	if err := s.save(note); err != nil {
		return nil, err
	}
	src.LogAction("VAULT_SAVED", note)
	return s.withSnapshot(map[string]any{"moved": moved, "conflicts": conflicts}), nil
}

func hItemFavorite(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
		On  bool     `json:"on"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	n := 0
	for _, id := range in.IDs {
		if _, ok := s.vault.FindItem(id); ok {
			s.setFavorite(id, in.On)
			n++
		}
	}
	verb := "Starred"
	if !in.On {
		verb = "Unstarred"
	}
	if err := s.save(fmt.Sprintf("%s %d item(s)", verb, n)); err != nil {
		return nil, err
	}
	return s.withSnapshot(map[string]any{"count": n}), nil
}

func hItemRestoreVersion(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID    string `json:"id"`
		Index int    `json:"index"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	d := s.desktop()
	list := d.Versions[in.ID]
	if in.Index < 0 || in.Index >= len(list) {
		return nil, rpcErr("not_found", "That version no longer exists.")
	}
	f := map[string]any{}
	for k, v := range list[in.Index].F {
		if k != "file" {
			f[k] = v
		}
	}
	ref, err := s.updateItem(in.ID, f, nil, true)
	if err != nil {
		return nil, err
	}
	note := "Restored an earlier version of " + ref.Title
	if err := s.save(note); err != nil {
		return nil, err
	}
	src.LogAction("VAULT_SAVED", note)
	item, _ := s.itemByID(ref.ID)
	return s.withSnapshot(map[string]any{"item": item}), nil
}

func hItemUseCode(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	ref, ok := s.vault.FindItem(in.ID)
	if !ok || ref.Spec.ID != "recovery" {
		return nil, rpcErr("not_found", "That recovery code list no longer exists.")
	}
	e := &s.vault.RecoveryCodeItems[ref.Index]
	code := strings.TrimSpace(in.Code)
	found := false
	for _, c := range e.Codes {
		if c == code {
			found = true
		}
	}
	if !found {
		return nil, rpcErr("not_found", "That code is not in this list.")
	}
	for _, u := range e.Used {
		if u == code {
			return s.withSnapshot(nil), nil
		}
	}
	e.Used = append(e.Used, code)
	s.vault.LogItemEvent("EDIT", ref.Spec, ref.Title, ref.Space)
	if err := s.save("Marked a recovery code used on " + ref.Title); err != nil {
		return nil, err
	}
	return s.withSnapshot(nil), nil
}

func (s *desktopServer) fileFor(id string) (string, []byte, error) {
	if ref, ok := s.vault.FindItem(id); ok {
		name, content, ok := s.vault.ItemFileContent(ref)
		if !ok {
			return "", nil, rpcErr("invalid", "That item has no file.")
		}
		return name, content, nil
	}
	if i, ok := s.findTrash(id); ok {
		name, content, ok := s.vault.Desktop.Trash[i].FileContent()
		if !ok {
			return "", nil, rpcErr("invalid", "That item has no file.")
		}
		return name, content, nil
	}
	return "", nil, rpcErr("not_found", "That item no longer exists.")
}

func hItemFile(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	name, content, err := s.fileFor(in.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"name": name, "mime": src.MimeForFileName(name), "size": len(content), "data": base64.StdEncoding.EncodeToString(content)}, nil
}

func hItemSaveFile(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID   string `json:"id"`
		Path string `json:"path"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Path) == "" {
		return nil, rpcErr("invalid", "Choose where to save the file.")
	}
	name, content, err := s.fileFor(in.ID)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(in.Path, content, 0600); err != nil {
		return nil, err
	}
	src.LogAction("FILE_EXPORTED", name+" saved to "+in.Path)
	return map[string]any{"ok": true, "bytes": len(content)}, nil
}

func hItemImport(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Items []struct {
			Type  string         `json:"type"`
			Space string         `json:"space"`
			F     map[string]any `json:"f"`
		} `json:"items"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	added, skipped := 0, 0
	invalid := []string{}
	for _, it := range in.Items {
		if it.F == nil {
			skipped++
			continue
		}
		space := s.ensureSpace(normalizeSpaceParam(it.Space))
		if _, err := s.vault.AddItem(it.Type, space, it.F); err != nil {
			skipped++
			if !errors.Is(err, src.ErrItemExists) {
				invalid = append(invalid, err.Error())
			}
			continue
		}
		added++
	}
	if added > 0 {
		note := fmt.Sprintf("Imported %d item(s)", added)
		if err := s.save(note); err != nil {
			return nil, err
		}
		src.LogAction("DATA_IMPORTED", fmt.Sprintf("%d item(s) imported, %d skipped", added, skipped))
	}
	return s.withSnapshot(map[string]any{"added": added, "skipped": skipped, "errors": invalid}), nil
}

func hTOTPOrder(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	refs := map[string]src.VaultItemRef{}
	for _, r := range s.vault.ItemRefs() {
		refs[r.ID] = r
	}
	seen := map[string]bool{}
	var keys []string
	for _, id := range in.IDs {
		r, ok := refs[id]
		if !ok || !s.vault.HoldsTOTP(r) {
			continue
		}
		k := s.vault.TOTPOrderKey(r)
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for _, k := range s.vault.TOTPOrder {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	s.vault.TOTPOrder = keys
	if err := s.save("Reordered authenticator codes"); err != nil {
		return nil, err
	}
	return s.withSnapshot(nil), nil
}

func hPasskeyRemove(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		CredentialID string `json:"credentialId"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	i, j, ok := s.vault.PasskeyOwner(in.CredentialID)
	if !ok {
		return nil, rpcErr("not_found", "That passkey no longer exists.")
	}
	e := &s.vault.Entries[i]
	rp := e.Passkeys[j].RPID
	e.Passkeys = append(e.Passkeys[:j], e.Passkeys[j+1:]...)
	if err := s.save("Removed a passkey from " + e.Account); err != nil {
		return nil, err
	}
	src.LogAction("PASSKEY_DELETED", fmt.Sprintf("rpId=%s entry=%s", rp, e.Account))
	return s.withSnapshot(nil), nil
}

func hPasskeyRename(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		CredentialID string `json:"credentialId"`
		Label        string `json:"label"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	i, j, ok := s.vault.PasskeyOwner(in.CredentialID)
	if !ok {
		return nil, rpcErr("not_found", "That passkey no longer exists.")
	}
	label := strings.TrimSpace(in.Label)
	if r := []rune(label); len(r) > 120 {
		label = string(r[:120])
	}
	s.vault.Entries[i].Passkeys[j].Label = label
	if err := s.save("Renamed a passkey on " + s.vault.Entries[i].Account); err != nil {
		return nil, err
	}
	src.LogAction("PASSKEY_RENAMED", "entry="+s.vault.Entries[i].Account)
	return s.withSnapshot(nil), nil
}

func hSpaceAdd(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, rpcErr("invalid", "Give the space a name.")
	}
	if strings.EqualFold(name, "default") {
		return nil, rpcErr("exists", "A space called Default already exists.")
	}
	if _, ok := s.spaceExists(name); ok {
		return nil, rpcErr("exists", "A space called "+name+" already exists.")
	}
	used := map[int]bool{}
	for _, sp := range s.spacesView() {
		used[sp["color"].(int)] = true
	}
	color := len(used) % 7
	for c := 0; c < 7; c++ {
		if !used[c] {
			color = c
			break
		}
	}
	s.ensureSpace(name)
	d := s.desktop()
	if d.SpaceColors == nil {
		d.SpaceColors = map[string]int{}
	}
	d.SpaceColors[name] = color
	if err := s.save("Created space " + name); err != nil {
		return nil, err
	}
	src.LogAction("SPACE_CREATED", name)
	return s.withSnapshot(map[string]any{"space": map[string]any{"id": name, "name": name, "color": color}}), nil
}

func hSpaceRename(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	old, ok := s.spaceExists(in.ID)
	if !ok || strings.EqualFold(old, "default") {
		return nil, rpcErr("not_found", "That space no longer exists.")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, rpcErr("invalid", "Give the space a name.")
	}
	if other, exists := s.spaceExists(name); exists && other != old {
		return nil, rpcErr("exists", "A space called "+name+" already exists.")
	}
	if strings.EqualFold(name, "default") {
		return nil, rpcErr("exists", "A space called Default already exists.")
	}
	before := s.vault.ItemRefs()
	s.vault.RenameSpaceEverywhere(old, name)
	for i, sp := range s.vault.Spaces {
		if sp == old {
			s.vault.Spaces[i] = name
		}
	}
	s.remapByIndex(before, "", -1)
	d := s.desktop()
	if c, ok := d.SpaceColors[old]; ok {
		delete(d.SpaceColors, old)
		d.SpaceColors[name] = c
	}
	if c, ok := d.SpaceCreated[old]; ok {
		delete(d.SpaceCreated, old)
		d.SpaceCreated[name] = c
	}
	for i := range d.Trash {
		if d.Trash[i].Space == old {
			d.Trash[i].Space = name
		}
	}
	if err := s.save("Renamed space " + old + " to " + name); err != nil {
		return nil, err
	}
	src.LogAction("SPACE_RENAMED", old+" to "+name)
	return s.withSnapshot(nil), nil
}

func hSpaceDelete(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID     string `json:"id"`
		MoveTo string `json:"moveTo"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	old, ok := s.spaceExists(in.ID)
	if !ok || strings.EqualFold(old, "default") {
		return nil, rpcErr("not_found", "That space no longer exists.")
	}
	target := normalizeSpaceParam(in.MoveTo)
	if target != "" {
		existing, ok := s.spaceExists(target)
		if !ok || existing == old {
			return nil, rpcErr("invalid", "Choose another space to move the items to.")
		}
		target = existing
	}
	var ids []string
	var conflicts []string
	targetTitles := map[string]bool{}
	for _, r := range s.vault.ItemRefs() {
		if strings.EqualFold(r.Space, target) {
			targetTitles[r.Spec.ID+"\x00"+strings.ToLower(r.Title)] = true
		}
	}
	for _, r := range s.vault.ItemRefs() {
		if r.Space == old {
			if targetTitles[r.Spec.ID+"\x00"+strings.ToLower(r.Title)] {
				conflicts = append(conflicts, r.Title)
			}
			ids = append(ids, r.ID)
		}
	}
	if len(conflicts) > 0 {
		return nil, rpcErrData("exists", "These items already exist in the target space: "+strings.Join(conflicts, ", ")+".", map[string]any{"conflicts": conflicts})
	}
	for _, id := range ids {
		if _, err := s.updateItem(id, nil, &target, false); err != nil {
			return nil, err
		}
	}
	kept := s.vault.Spaces[:0:0]
	for _, sp := range s.vault.Spaces {
		if sp != old {
			kept = append(kept, sp)
		}
	}
	s.vault.Spaces = kept
	if s.vault.CurrentSpace == old {
		s.vault.CurrentSpace = ""
	}
	d := s.desktop()
	delete(d.SpaceColors, old)
	delete(d.SpaceCreated, old)
	for i := range d.Trash {
		if d.Trash[i].Space == old {
			d.Trash[i].Space = target
		}
	}
	if err := s.save("Deleted space " + old); err != nil {
		return nil, err
	}
	src.LogAction("SPACE_DELETED", fmt.Sprintf("%s, %d item(s) moved", old, len(ids)))
	return s.withSnapshot(map[string]any{"moved": len(ids)}), nil
}

func hSpaceColor(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID    string `json:"id"`
		Color int    `json:"color"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	name, ok := s.spaceExists(in.ID)
	if !ok {
		return nil, rpcErr("not_found", "That space no longer exists.")
	}
	if in.Color < 0 || in.Color > 6 {
		return nil, rpcErr("invalid", "Pick one of the seven space colors.")
	}
	d := s.desktop()
	if d.SpaceColors == nil {
		d.SpaceColors = map[string]int{}
	}
	d.SpaceColors[name] = in.Color
	if err := s.save("Recolored " + name); err != nil {
		return nil, err
	}
	return s.withSnapshot(nil), nil
}

func hChangePassword(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	res, next, err := func() (map[string]any, string, error) {
		if err := s.requireWritable(); err != nil {
			return nil, "", err
		}
		if subtle.ConstantTimeCompare([]byte(in.Current), []byte(s.password)) != 1 {
			return nil, "", rpcErr("wrong_password", "That is not your current master password.")
		}
		if err := src.ValidateMasterPassword(in.Next); err != nil {
			return nil, "", rpcErr("invalid", err.Error())
		}
		data, err := src.UpdateMasterPassword(s.vault, in.Current, in.Next)
		if err != nil {
			return nil, "", err
		}
		if err := s.writeVault(data, true, "Master password changed"); err != nil {
			return nil, "", err
		}
		s.password = in.Next
		_ = src.KillSession()
		_ = lockPolicyOf(s.vault).startSession(in.Next, false)
		src.SendAlert(s.vault, src.LevelSettings, "PASSWORD CHANGE", "Master password has been successfully rotated.")
		src.LogAction("MASTER_PASSWORD_CHANGED", "Changed from the desktop app")
		return map[string]any{"ok": true}, in.Next, nil
	}()
	touch := err == nil && s.touchIDConfigured()
	if err != nil {
		return nil, err
	}
	if touch {
		if terr := storeTouchID(next); terr != nil {
			res["touchIdError"] = "Touch ID was not updated: " + terr.Error()
		} else {
			res["touchIdUpdated"] = true
		}
	}
	res["snapshot"] = s.snapshot()
	return res, nil
}

func hSecurityProfile(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Profile string               `json:"profile"`
		Custom  *customProfileParams `json:"custom"`
		Cipher  string               `json:"cipher"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	params, name, err := buildCryptoProfile(in.Profile, in.Custom, in.Cipher)
	if err != nil {
		return nil, err
	}
	old := "custom"
	if s.vault.CurrentProfileParams != nil {
		old = builtinProfileName(*s.vault.CurrentProfileParams)
	}
	s.vault.Profile = name
	s.vault.CurrentProfileParams = &params
	label := name
	if name == "custom" {
		label = "a custom"
	}
	if err := s.save("Re-encrypted with " + label + " profile"); err != nil {
		return nil, err
	}
	src.LogAction("PROFILE_CHANGED", fmt.Sprintf("%s to %s, cipher %s", old, name, displayCipher(params.Cipher)))
	return s.withSnapshot(nil), nil
}

// storeTouchID saves the master password for Touch ID. Every caller has just
// confirmed the master password, so under the desktop app there is no
// fingerprint prompt on top; on its own pm keeps the CLI's prompt.
func storeTouchID(password string) error {
	if touchIDByApp() {
		return touchid.Store(password)
	}
	return touchid.Setup(password)
}

func hSecurityTouchID(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		On       bool   `json:"on"`
		Password string `json:"password"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err := s.requireWritable(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if !s.touchIDAvailable() {
		s.mu.Unlock()
		return nil, rpcErr("touchid_unavailable", "Touch ID is not available on this Mac.")
	}
	pass := s.password
	if in.On && in.Password != "" && subtle.ConstantTimeCompare([]byte(in.Password), []byte(s.password)) != 1 {
		s.mu.Unlock()
		return nil, rpcErr("wrong_password", "That is not your master password.")
	}
	s.mu.Unlock()
	var err error
	if in.On {
		err = storeTouchID(pass)
	} else if touchIDByApp() {
		err = touchid.Delete()
	} else {
		err = touchid.Remove()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if errors.Is(err, touchid.ErrAuthFailed) {
			return nil, rpcErr("touchid_failed", "Touch ID was cancelled or did not match.")
		}
		return nil, rpcErr("touchid_failed", err.Error())
	}
	s.touchConf = -1
	if in.On {
		src.LogAction("TOUCHID_ENABLED", "Configured from the desktop app")
	} else {
		src.LogAction("TOUCHID_REMOVED", "Removed from the desktop app")
	}
	if !s.unlocked() {
		return map[string]any{"ok": true}, nil
	}
	return s.withSnapshot(nil), nil
}

func hPolicyLoad(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	policies, err := src.LoadPolicies(s.policyDir())
	if err != nil {
		return nil, err
	}
	for _, pol := range policies {
		if pol.Name == in.Name {
			s.vault.ActivePolicy = pol
			s.desktop().Policy = pol.Name
			if err := s.save("Loaded policy " + pol.Name); err != nil {
				return nil, err
			}
			src.LogAction("POLICY_LOADED", "Policy: "+pol.Name)
			return s.withSnapshot(nil), nil
		}
	}
	return nil, rpcErr("not_found", "Policy "+in.Name+" was not found in "+s.policyDir()+".")
}

func hPolicyClear(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	s.vault.ActivePolicy = src.Policy{}
	s.desktop().Policy = ""
	if err := s.save("Cleared policy"); err != nil {
		return nil, err
	}
	src.LogAction("POLICY_CLEARED", "Active policy removed")
	return s.withSnapshot(nil), nil
}

func sixDigitCode() (string, [32]byte, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", [32]byte{}, err
	}
	for i := range b {
		b[i] = '0' + (b[i] % 10)
	}
	code := string(b)
	return code, sha256.Sum256([]byte(code)), nil
}

func codeMatches(entered string, hash [32]byte) bool {
	entered = strings.TrimSpace(strings.ReplaceAll(entered, " ", ""))
	h := sha256.Sum256([]byte(entered))
	return subtle.ConstantTimeCompare(h[:], hash[:]) == 1
}

func validEmail(e string) bool {
	e = strings.TrimSpace(e)
	at := strings.LastIndex(e, "@")
	return at > 0 && at < len(e)-3 && strings.Contains(e[at:], ".") && !strings.ContainsAny(e, " \t\r\n")
}

func hRecoveryEmailStart(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Email string `json:"email"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	s.mu.Lock()
	if err := s.requireWritable(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()
	if !validEmail(email) {
		return nil, rpcErr("invalid", "Enter a valid email address.")
	}
	code, hash, err := sixDigitCode()
	if err != nil {
		return nil, err
	}
	if err := desktopSendMail(email, code+" - APM Email Verification", "Verify your email for recovery setup", []string{
		"Use this code to verify ownership of this email for vault recovery setup.",
		"This code expires in 15 minutes.",
	}, code, []string{"If you did not request this, ignore this email."}); err != nil {
		return nil, rpcErr("network", "Could not send the verification email: "+err.Error())
	}
	s.mu.Lock()
	s.emailSetup = &emailSetupState{email: email, codeHash: hash, sent: time.Now()}
	s.mu.Unlock()
	return map[string]any{"ok": true, "sent": true, "expiresIn": 900}, nil
}

func hRecoveryEmailVerify(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Code string `json:"code"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	res, email, err := func() (map[string]any, string, error) {
		if err := s.requireWritable(); err != nil {
			return nil, "", err
		}
		st := s.emailSetup
		if st == nil {
			return nil, "", rpcErr("invalid", "Send a verification code first.")
		}
		if time.Since(st.sent) > 15*time.Minute {
			s.emailSetup = nil
			return nil, "", rpcErr("invalid", "The code expired. Send a new one.")
		}
		if !codeMatches(in.Code, st.codeHash) {
			st.attempts++
			left := 5 - st.attempts
			if left <= 0 {
				s.emailSetup = nil
				return nil, "", rpcErrData("invalid", "Too many wrong codes. Send a new one.", map[string]any{"left": 0})
			}
			return nil, "", rpcErrData("invalid", "That code is not correct.", map[string]any{"left": left})
		}
		s.emailSetup = nil
		v := s.vault
		v.SetRecoveryEmail(st.email)
		if v.CurrentProfileParams == nil {
			prof := src.GetProfile(v.Profile)
			v.CurrentProfileParams = &prof
		}
		key, err := s.installRecoveryKey()
		if err != nil {
			return nil, "", err
		}
		if err := s.save("Recovery email set"); err != nil {
			return nil, "", err
		}
		src.LogAction("RECOVERY_EMAIL_SET", src.MaskEmailHint(st.email))
		return map[string]any{"ok": true, "key": key}, st.email, nil
	}()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if merr := desktopSendMail(email, "SECURITY ALERT: APM Vault Recovery Configured", "Recovery access has been configured for your APM vault", []string{
		"For your security, the recovery key was not sent in this email.",
		"It was displayed only once in the APM desktop app during setup.",
		"This is a zero-knowledge system: we cannot recover your vault without your physical recovery key.",
	}, "", []string{
		"If you did not initiate this setup, your vault may be compromised.",
		"Change your master password immediately.",
	}); merr != nil {
		res["alertError"] = merr.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unlocked() {
		res["snapshot"] = s.snapshot()
	}
	return res, nil
}

func (s *desktopServer) installRecoveryKey() (string, error) {
	v := s.vault
	if v.CurrentProfileParams == nil {
		prof := src.GetProfile(v.Profile)
		v.CurrentProfileParams = &prof
	}
	key := src.GenerateRecoveryKey()
	saltLen := v.CurrentProfileParams.SaltLen
	if saltLen <= 0 {
		saltLen = 16
	}
	salt, err := src.GenerateSalt(saltLen)
	if err != nil {
		return "", err
	}
	if err := v.SetRecoveryKey(key, salt); err != nil {
		return "", err
	}
	v.RecoveryShareThreshold = 0
	v.RecoveryShareCount = 0
	v.RecoveryShareHashes = nil
	s.desktop().RecoveryKeyCreated = time.Now()
	s.desktop().QuorumCreated = time.Time{}
	return key, nil
}

func hRecoveryKeyCreate(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if s.vault.RecoveryEmail == "" {
		return nil, rpcErr("invalid", "Set up a recovery email first. Recovery with a key also needs the emailed code.")
	}
	hadQuorum := s.vault.RecoveryShareThreshold > 0
	key, err := s.installRecoveryKey()
	if err != nil {
		return nil, err
	}
	if err := s.save("Recovery key created"); err != nil {
		return nil, err
	}
	src.LogAction("RECOVERY_KEY_CREATED", "New recovery key issued from the desktop app")
	return s.withSnapshot(map[string]any{"key": key, "quorumCleared": hadQuorum}), nil
}

func hRecoveryCodesGenerate(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Count int `json:"count"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if in.Count <= 0 {
		in.Count = 10
	}
	if in.Count > 20 {
		return nil, rpcErr("invalid", "Generate at most 20 codes at a time.")
	}
	codes, err := src.GenerateOneTimeRecoveryCodes(s.vault, in.Count)
	if err != nil {
		return nil, rpcErr("invalid", err.Error())
	}
	s.desktop().RecoveryCodesCreated = time.Now()
	if err := s.save("One-time recovery codes generated"); err != nil {
		return nil, err
	}
	src.LogAction("RECOVERY_CODES_GENERATED", fmt.Sprintf("Generated %d recovery codes", len(codes)))
	return s.withSnapshot(map[string]any{"codes": codes}), nil
}

func hRecoveryPasskeyRegister(s *desktopServer, p json.RawMessage) (any, error) {
	s.mu.Lock()
	if err := s.requireWritable(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()
	userID, cred, err := src.RunRecoveryPasskeyRegistration()
	if err != nil {
		return nil, rpcErr("invalid", "Passkey registration failed: "+err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	s.vault.RecoveryPasskeyEnabled = true
	s.vault.RecoveryPasskeyUserID = userID
	s.vault.RecoveryPasskeyCred = cred
	if err := s.save("Recovery passkey registered"); err != nil {
		return nil, err
	}
	src.LogAction("RECOVERY_PASSKEY_REGISTERED", "Registered recovery passkey")
	return s.withSnapshot(nil), nil
}

func hRecoveryPasskeyRemove(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	s.vault.RecoveryPasskeyEnabled = false
	s.vault.RecoveryPasskeyUserID = nil
	s.vault.RecoveryPasskeyCred = nil
	if err := s.save("Recovery passkey removed"); err != nil {
		return nil, err
	}
	src.LogAction("RECOVERY_PASSKEY_DISABLED", "Disabled recovery passkey")
	return s.withSnapshot(nil), nil
}

func hRecoveryQuorumSetup(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Threshold int    `json:"threshold"`
		Shares    int    `json:"shares"`
		Key       string `json:"key"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if s.vault.RecoveryEmail == "" && len(s.vault.RecoveryHash) == 0 {
		return nil, rpcErr("invalid", "Set up a recovery email and key first.")
	}
	if in.Shares > 10 {
		return nil, rpcErr("invalid", "Use at most 10 shares.")
	}
	shareMap, err := src.SetupRecoveryQuorumWithKey(s.vault, strings.TrimSpace(in.Key), in.Threshold, in.Shares)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "provide the recovery key") {
			return nil, rpcErrData("invalid", "Enter your recovery key to split it into shares.", map[string]any{"needKey": true})
		}
		return nil, rpcErr("invalid", err.Error())
	}
	shares := make([]string, 0, len(shareMap))
	for i := 1; i <= in.Shares; i++ {
		shares = append(shares, shareMap[i])
	}
	s.desktop().QuorumCreated = time.Now()
	if err := s.save("Trustee shares created"); err != nil {
		return nil, err
	}
	src.LogAction("RECOVERY_QUORUM_CONFIGURED", fmt.Sprintf("Configured %d-of-%d quorum recovery", in.Threshold, in.Shares))
	return s.withSnapshot(map[string]any{"shares": shares}), nil
}

func hRecoveryReset(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	s.vault.ClearRecoveryInfo()
	d := s.desktop()
	d.RecoveryKeyCreated = time.Time{}
	d.RecoveryCodesCreated = time.Time{}
	d.QuorumCreated = time.Time{}
	if err := s.save("Recovery data removed"); err != nil {
		return nil, err
	}
	src.SendAlert(s.vault, src.LevelSettings, "RECOVERY RESET", "Recovery email and associated metadata have been cleared.")
	src.LogAction("RECOVERY_RESET", "Recovery email and records removed")
	return s.withSnapshot(nil), nil
}

func (r *recoverState) needsSecondFactor() bool {
	return r.info.RecoveryPasskeyEnabled || len(r.info.RecoveryCodeHashes) > 0
}

func (r *recoverState) ready() bool {
	if r == nil || len(r.dek) == 0 {
		return false
	}
	if r.via == "quorum" {
		return r.emailOK || len(r.info.EmailHash) == 0
	}
	if !r.emailOK || !r.codeVerified {
		return false
	}
	return r.secondOK || !r.needsSecondFactor()
}

func (r *recoverState) view() map[string]any {
	return map[string]any{
		"emailVerified":      r.emailOK,
		"codeSent":           !r.codeSent.IsZero(),
		"codeVerified":       r.codeVerified,
		"keyVerified":        len(r.dek) > 0,
		"via":                r.via,
		"secondFactorOK":     r.secondOK,
		"needsSecondFactor":  r.needsSecondFactor(),
		"ready":              r.ready(),
		"recoveryCodeUnused": unusedHeaderCodes(r.info),
	}
}

func unusedHeaderCodes(info src.RecoveryData) int {
	n := 0
	for i := range info.RecoveryCodeHashes {
		if i >= len(info.RecoveryCodeUsed) || !info.RecoveryCodeUsed[i] {
			n++
		}
	}
	return n
}

func hRecoverStart(s *desktopServer, p json.RawMessage) (any, error) {
	if !src.VaultExists(s.vaultPath) {
		return nil, rpcErr("no_vault", "No vault found at "+s.vaultPath+".")
	}
	data, err := src.LoadVault(s.vaultPath)
	if err != nil {
		return nil, err
	}
	info, ok := src.ParseVaultHeaderRecovery(data)
	if !ok {
		return nil, rpcErr("unsupported", "This vault version does not support recovery.")
	}
	s.rec = &recoverState{data: data, info: info, usedCodeIndex: -1}
	email := len(info.EmailHash) > 0
	methods := map[string]any{
		"email":   email,
		"key":     email && len(info.KeyHash) > 0 && len(info.DEKSlot) > 0,
		"codes":   unusedHeaderCodes(info) > 0,
		"passkey": info.RecoveryPasskeyEnabled && len(info.RecoveryPasskeyCred) > 0,
		"quorum":  info.RecoveryShareThreshold >= 2 && len(info.RecoveryShareHashes) > 0,
	}
	res := map[string]any{"ok": true, "methods": methods, "emailHint": info.EmailHint, "threshold": info.RecoveryShareThreshold, "state": s.rec.view()}
	return res, nil
}

func (s *desktopServer) checkRecoveryEmail(email string) error {
	r := s.rec
	if r == nil {
		return rpcErr("invalid", "Start recovery first.")
	}
	if len(r.info.EmailHash) == 0 {
		return rpcErr("invalid", "This vault has no recovery email.")
	}
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	if subtle.ConstantTimeCompare(h[:], r.info.EmailHash) != 1 {
		return rpcErr("invalid", "That email does not match the recovery email for this vault.")
	}
	r.emailOK = true
	r.email = strings.ToLower(strings.TrimSpace(email))
	return nil
}

func hRecoverEmailSend(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Email string `json:"email"`
		Send  *bool  `json:"send"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err := s.checkRecoveryEmail(in.Email); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	r := s.rec
	s.mu.Unlock()
	if in.Send != nil && !*in.Send {
		s.mu.Lock()
		defer s.mu.Unlock()
		return map[string]any{"ok": true, "sent": false, "state": r.view()}, nil
	}
	code, hash, err := sixDigitCode()
	if err != nil {
		return nil, err
	}
	if err := desktopSendMail(r.email, code+" - APM Recovery Verification Code", "Verify your email for vault recovery", []string{
		"We received a recovery attempt for your APM vault.",
		"Enter this 6-digit code in the APM desktop app.",
		"This code expires in 15 minutes and is valid only for this recovery flow.",
	}, code, []string{
		"Never share this code.",
		"APM support will never ask for this code.",
		"If this was not you, ignore this message and rotate your master password.",
	}); err != nil {
		return nil, rpcErr("network", "Could not send the recovery email: "+err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rec != r {
		return nil, rpcErr("invalid", "Recovery was restarted.")
	}
	r.codeHash = hash
	r.codeSent = time.Now()
	r.codeAttempts = 0
	r.codeVerified = false
	return map[string]any{"ok": true, "sent": true, "expiresIn": 900, "state": r.view()}, nil
}

func hRecoverEmailVerify(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Code string `json:"code"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	r := s.rec
	if r == nil || r.codeSent.IsZero() {
		return nil, rpcErr("invalid", "Send the email code first.")
	}
	if time.Since(r.codeSent) > 15*time.Minute {
		r.codeSent = time.Time{}
		return nil, rpcErr("invalid", "The code expired. Send a new one.")
	}
	if !codeMatches(in.Code, r.codeHash) {
		r.codeAttempts++
		left := 5 - r.codeAttempts
		if left <= 0 {
			r.codeSent = time.Time{}
			return nil, rpcErrData("invalid", "Too many wrong codes. Send a new one.", map[string]any{"left": 0})
		}
		return nil, rpcErrData("invalid", "That code is not correct.", map[string]any{"left": left})
	}
	r.codeVerified = true
	r.codeHash = [32]byte{}
	return map[string]any{"ok": true, "state": r.view()}, nil
}

func hRecoverVerify(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Method string   `json:"method"`
		Value  string   `json:"value"`
		Shares []string `json:"shares"`
		Email  string   `json:"email"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	r := s.rec
	if r == nil {
		s.mu.Unlock()
		return nil, rpcErr("invalid", "Start recovery first.")
	}
	if in.Method == "passkey" {
		info := r.info
		s.mu.Unlock()
		if !info.RecoveryPasskeyEnabled {
			return nil, rpcErr("invalid", "This vault has no recovery passkey.")
		}
		if err := src.VerifyRecoveryPasskeyFromHeader(info); err != nil {
			return nil, rpcErr("invalid", "Passkey verification failed: "+err.Error())
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.rec != r {
			return nil, rpcErr("invalid", "Recovery was restarted.")
		}
		r.secondOK = true
		return map[string]any{"ok": true, "ready": r.ready(), "state": r.view()}, nil
	}
	defer s.mu.Unlock()
	switch in.Method {
	case "key":
		if !r.emailOK {
			return nil, rpcErr("invalid", "Confirm your recovery email first.")
		}
		dek, err := src.CheckRecoveryKey(r.data, strings.TrimSpace(in.Value))
		if err != nil {
			r.keyAttempts++
			left := 3 - r.keyAttempts
			if left <= 0 {
				s.rec = nil
				return nil, rpcErrData("invalid", "Too many wrong recovery keys. Start recovery again.", map[string]any{"left": 0, "restart": true})
			}
			return nil, rpcErrData("invalid", "That recovery key is not correct.", map[string]any{"left": left})
		}
		r.dek = dek
		r.via = "key"
	case "quorum":
		if len(r.info.EmailHash) > 0 && !r.emailOK {
			if strings.TrimSpace(in.Email) == "" {
				return nil, rpcErr("invalid", "Confirm your recovery email first.")
			}
			if err := s.checkRecoveryEmail(in.Email); err != nil {
				return nil, err
			}
		}
		temp := &src.Vault{RecoveryShareThreshold: r.info.RecoveryShareThreshold, RecoveryShareCount: r.info.RecoveryShareCount, RecoveryShareHashes: r.info.RecoveryShareHashes}
		var shares []string
		for _, sh := range in.Shares {
			if strings.TrimSpace(sh) != "" {
				shares = append(shares, strings.TrimSpace(sh))
			}
		}
		if len(shares) < r.info.RecoveryShareThreshold {
			return nil, rpcErr("invalid", fmt.Sprintf("Enter at least %d shares.", r.info.RecoveryShareThreshold))
		}
		key, err := src.CombineRecoveryQuorumShares(temp, shares)
		if err != nil {
			return nil, rpcErr("invalid", "Share verification failed: "+err.Error())
		}
		dek, err := src.CheckRecoveryKey(r.data, key)
		if err != nil {
			return nil, rpcErr("invalid", "The shares did not rebuild a valid recovery key.")
		}
		r.dek = dek
		r.via = "quorum"
	case "code":
		idx, ok := src.ValidateRecoveryCodeFromHeader(r.info, in.Value)
		if !ok {
			return nil, rpcErr("invalid", "That recovery code is not valid or was already used.")
		}
		r.secondOK = true
		r.usedCodeIndex = idx
	default:
		return nil, rpcErr("invalid", "Unknown recovery method.")
	}
	return map[string]any{"ok": true, "ready": r.ready(), "state": r.view()}, nil
}

func hRecoverReset(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	res, err := func() (map[string]any, error) {
		r := s.rec
		if !r.ready() {
			return nil, rpcErr("invalid", "Finish the recovery checks first.")
		}
		if err := src.ValidateMasterPassword(in.Password); err != nil {
			return nil, rpcErr("invalid", err.Error())
		}
		v, err := src.DecryptVaultWithDEK(r.data, r.dek)
		if err != nil {
			return nil, rpcErr("internal", "Could not open the vault with the recovered key: "+err.Error())
		}
		v.FailedAttempts = 0
		v.EmergencyMode = false
		if r.usedCodeIndex >= 0 {
			src.MarkRecoveryCodeUsed(v, r.usedCodeIndex)
		}
		data, err := src.EncryptVault(v, in.Password)
		if err != nil {
			return nil, err
		}
		if err := s.writeVault(data, true, "Master password reset with recovery"); err != nil {
			return nil, err
		}
		src.ClearFailures()
		src.SendAlert(v, src.LevelCritical, "RECOVERY SUCCESS", "Vault has been successfully recovered and master password reset.")
		if r.via == "quorum" {
			src.LogAction("RECOVERY_QUORUM_SUCCESS", "Vault recovered with quorum shares")
		} else {
			src.LogAction("RECOVERY_COMPLETED", "Master password reset with the recovery key")
		}
		s.rec = nil
		return s.finishUnlock(in.Password, v, "recovery", true), nil
	}()
	touch := err == nil && s.touchIDConfigured()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if touch {
		if terr := storeTouchID(in.Password); terr != nil {
			res["touchIdError"] = "Touch ID was not updated: " + terr.Error()
		}
	}
	return res, nil
}

func (s *desktopServer) afterLGitChange() error {
	return s.reloadFromDisk()
}

func hLGitUndo(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Steps int `json:"steps"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if in.Steps < 1 {
		in.Steps = 1
	}
	done := 0
	var undoErr error
	for i := 0; i < in.Steps; i++ {
		if err := src.UndoLGit(s.vaultPath); err != nil {
			undoErr = err
			break
		}
		done++
	}
	if done == 0 {
		return nil, rpcErr("invalid", "Nothing to undo: "+undoErr.Error())
	}
	if head, err := src.GetLGitHead(); err == nil && head != nil {
		_ = src.SetLGitNote(head.ID, fmt.Sprintf("Back %d step(s)", done))
	}
	src.LogAction("LGIT_UNDO", fmt.Sprintf("Undid %d lgit change(s)", done))
	if err := s.afterLGitChange(); err != nil {
		return nil, err
	}
	return s.withSnapshot(map[string]any{"steps": done}), nil
}

func hLGitCheckout(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	commit, _, err := src.FindLGitCommitByPrefix(strings.TrimSpace(in.ID))
	if err != nil || commit == nil {
		return nil, rpcErr("not_found", "Commit "+in.ID+" was not found.")
	}
	if commit.VaultPath != "" && filepath.Clean(commit.VaultPath) != s.vaultPath {
		return nil, rpcErr("invalid", "That commit belongs to a different vault.")
	}
	if err := src.CheckoutLGit(s.vaultPath, commit.ID); err != nil {
		return nil, rpcErr("invalid", "Checkout failed: "+err.Error())
	}
	short := commit.ID
	if len(short) > 12 {
		short = short[len(short)-12:]
	}
	if head, err := src.GetLGitHead(); err == nil && head != nil {
		_ = src.SetLGitNote(head.ID, "Restored "+short)
	}
	src.LogAction("LGIT_CHECKOUT", "Checked out lgit commit="+commit.ID)
	if err := s.afterLGitChange(); err != nil {
		return nil, err
	}
	return s.withSnapshot(nil), nil
}

func hLGitSquash(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Keep int `json:"keep"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if in.Keep < 1 {
		in.Keep = 1
	}
	before, _ := src.GetLGitCommits(0)
	if err := src.SquashLGitHistory(s.vaultPath, in.Keep); err != nil {
		return nil, rpcErr("invalid", "Squash failed: "+err.Error())
	}
	after, _ := src.GetLGitCommits(0)
	removed := len(before) - len(after) + 1
	if len(before) <= in.Keep {
		removed = 0
	}
	if head, err := src.GetLGitHead(); err == nil && head != nil && removed > 0 {
		_ = src.SetLGitNote(head.ID, fmt.Sprintf("Kept the last %d", in.Keep))
	}
	src.LogAction("LGIT_SQUASH", fmt.Sprintf("Squashed lgit history, kept=%d", in.Keep))
	if data, err := os.ReadFile(s.vaultPath); err == nil {
		s.lastWriteHash = sha256Hex(data)
	}
	return s.withSnapshot(map[string]any{"removed": removed}), nil
}

func hLGitPrune(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	removed, kept, err := src.PruneLGitSnapshots()
	if err != nil {
		return nil, err
	}
	src.LogAction("LGIT_PRUNE", fmt.Sprintf("Pruned lgit snapshots removed=%d kept=%d", removed, kept))
	return s.withSnapshot(map[string]any{"removed": removed, "kept": kept}), nil
}

func hLGitVerify(s *desktopServer, p json.RawMessage) (any, error) {
	good, total, err := src.VerifyLGitHistory()
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": good == total, "good": good, "total": total}, nil
}

func hSessionsIssue(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Label    string `json:"label"`
		Agent    string `json:"agent"`
		Scope    string `json:"scope"`
		Minutes  int    `json:"minutes"`
		BindHost *bool  `json:"bindHost"`
		BindPid  bool   `json:"bindPid"`
		Pid      int    `json:"pid"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	scope := strings.ToLower(strings.TrimSpace(in.Scope))
	if scope == "" {
		scope = "read"
	}
	if scope != "read" && scope != "write" {
		return nil, rpcErr("invalid", "Scope must be read or write.")
	}
	if in.Minutes <= 0 {
		in.Minutes = 15
	}
	if in.Minutes > 24*60 {
		return nil, rpcErr("invalid", "Sessions can last at most 24 hours.")
	}
	bindHost := true
	if in.BindHost != nil {
		bindHost = *in.BindHost
	}
	pid := 0
	if in.BindPid {
		pid = in.Pid
		if pid <= 0 {
			pid = os.Getpid()
		}
	}
	eph, err := src.IssueEphemeralSession(s.password, strings.TrimSpace(in.Label), scope, strings.TrimSpace(in.Agent), time.Duration(in.Minutes)*time.Minute, bindHost, pid)
	if err != nil {
		return nil, rpcErr("invalid", err.Error())
	}
	env := "APM_EPHEMERAL_ID=" + eph.ID
	if eph.BoundAgent != "" {
		env += " APM_EPHEMERAL_AGENT=" + eph.BoundAgent
	}
	view := map[string]any{"id": eph.ID, "label": eph.Label, "agent": eph.BoundAgent, "scope": eph.Scope, "created": ms(eph.CreatedAt), "expires": ms(eph.ExpiresAt), "bindHost": eph.BoundHostHash != "", "bindPid": eph.BoundPID > 0, "revoked": false}
	return s.withSnapshot(map[string]any{"id": eph.ID, "session": view, "env": env}), nil
}

func hSessionsRevoke(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	ok, err := src.RevokeEphemeralSession(in.ID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, rpcErr("not_found", "That session no longer exists.")
	}
	return s.withSnapshot(nil), nil
}

func hMCPEnabled(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		On bool `json:"on"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	s.desktop().MCPEnabled = in.On
	action := "MCP_DISABLED"
	if in.On {
		action = "MCP_ENABLED"
	}
	if err := s.save("AI access changed"); err != nil {
		return nil, err
	}
	src.LogAction(action, "Changed from the desktop app")
	return s.withSnapshot(nil), nil
}

func hMCPClient(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Name string `json:"name"`
		On   bool   `json:"on"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, rpcErr("invalid", "Client name is required.")
	}
	d := s.desktop()
	if d.MCPClients == nil {
		d.MCPClients = map[string]bool{}
	}
	d.MCPClients[name] = in.On
	if err := s.save("AI client " + name + " changed"); err != nil {
		return nil, err
	}
	return s.withSnapshot(nil), nil
}

func validMCPPerm(perm string) bool {
	for _, p := range src.MCPToolPermissions() {
		if p == perm {
			return true
		}
	}
	switch perm {
	case "read", "write", "secrets", "admin", "all", "*":
		return true
	}
	return false
}

func hMCPTokenCreate(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Name           string   `json:"name"`
		Perms          []string `json:"perms"`
		ExpiresMinutes int      `json:"expiresMinutes"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, rpcErr("invalid", "Name the token after the app that will use it.")
	}
	if len(in.Perms) == 0 {
		return nil, rpcErr("invalid", "Pick at least one permission.")
	}
	for _, perm := range in.Perms {
		if !validMCPPerm(perm) {
			return nil, rpcErr("invalid", "Unknown permission "+perm+".")
		}
	}
	if in.ExpiresMinutes < 0 {
		in.ExpiresMinutes = 0
	}
	token, err := src.GenerateMCPToken(name, in.Perms, in.ExpiresMinutes)
	if err != nil {
		return nil, err
	}
	cfg, _ := json.MarshalIndent(buildMCPConfigForToken(token), "", "  ")
	return s.withSnapshot(map[string]any{"token": token, "id": mcpTokenID(token), "config": string(cfg)}), nil
}

func hMCPTokenRevoke(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	list, err := src.ListMCPTokens()
	if err != nil {
		return nil, err
	}
	for _, t := range list {
		if mcpTokenID(t.Token) == in.ID {
			if _, err := src.RevokeMCPToken(t.Token); err != nil {
				return nil, err
			}
			return s.withSnapshot(nil), nil
		}
	}
	return nil, rpcErr("not_found", "That token no longer exists.")
}

func hMCPTxApprove(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	tx, err := src.GetMCPTransaction(in.ID)
	if err != nil {
		return nil, rpcErr("not_found", "That request expired or no longer exists.")
	}
	if tx.Status != "pending" {
		return nil, rpcErr("invalid", "That request is already "+tx.Status+".")
	}
	prevSpace := s.vault.CurrentSpace
	prevActor, hadActor := os.LookupEnv("APM_ACTOR")
	_ = os.Setenv("APM_ACTOR", "AI")
	summary, applyErr := src.ApplyMCPTransaction(s.vault, tx.Tool, tx.Args)
	if hadActor {
		_ = os.Setenv("APM_ACTOR", prevActor)
	} else {
		_ = os.Unsetenv("APM_ACTOR")
	}
	s.vault.CurrentSpace = prevSpace
	if applyErr != nil {
		if data, err := os.ReadFile(s.vaultPath); err == nil {
			if v, derr := src.DecryptVault(data, s.password, 1); derr == nil {
				s.vault = v
			}
		}
		return nil, rpcErr("invalid", "Could not apply the request: "+applyErr.Error())
	}
	note := "Approved " + tx.TokenName + ": " + tx.Preview
	if err := s.save(note); err != nil {
		return nil, err
	}
	receipt, _ := src.FinalizeMCPTransaction(tx.ID, summary, true)
	action := map[string]string{"add_entry": "MCP_ENTRY_ADDED", "edit_entry": "MCP_ENTRY_EDITED", "delete_entry": "MCP_ENTRY_DELETED"}[tx.Tool]
	if action == "" {
		action = "MCP_TX_APPROVED"
	}
	src.LogAction(action, fmt.Sprintf("Approved in the desktop app for token '%s': %s", tx.TokenName, tx.Preview))
	s.knownTx[tx.ID] = true
	return s.withSnapshot(map[string]any{"receipt": receipt}), nil
}

func hMCPTxAbort(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	tx, err := src.GetMCPTransaction(in.ID)
	if err != nil {
		return nil, rpcErr("not_found", "That request expired or no longer exists.")
	}
	if err := src.AbortMCPTransaction(tx.ID); err != nil {
		return nil, err
	}
	src.LogAction("MCP_TX_ABORTED", fmt.Sprintf("Rejected in the desktop app for token '%s': %s", tx.TokenName, tx.Preview))
	s.knownTx[tx.ID] = true
	return s.withSnapshot(nil), nil
}

func hMCPConfig(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Client string `json:"client"`
		Token  string `json:"token"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	token := strings.TrimSpace(in.Token)
	if token == "" {
		token = "<your token>"
	}
	cfg, _ := json.MarshalIndent(buildMCPConfigForToken(token), "", "  ")
	return map[string]any{"json": string(cfg), "files": src.FindMCPConfigFiles()}, nil
}

func exportedCount(v *src.Vault, format string) int {
	n := len(v.Entries)
	if format == "csv" {
		return n
	}
	return n + len(v.AllTOTPs()) + len(v.Tokens) + len(v.SecureNotes) + len(v.APIKeys) + len(v.SSHKeys) + len(v.WiFiCredentials) + len(v.RecoveryCodeItems)
}

func hDataExport(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Format           string `json:"format"`
		Path             string `json:"path"`
		Password         string `json:"password"`
		WithoutPasswords bool   `json:"withoutPasswords"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Path) == "" {
		return nil, rpcErr("invalid", "Choose where to save the export.")
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	var err error
	switch format {
	case "json":
		err = src.ExportToJSON(s.vault, in.Path, in.Password)
	case "csv":
		err = src.ExportToCSV(s.vault, in.Path)
	case "txt":
		err = src.ExportToTXT(s.vault, in.Path, in.WithoutPasswords)
	default:
		return nil, rpcErr("invalid", "Export format must be json, csv or txt.")
	}
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(in.Path, 0600)
	count := exportedCount(s.vault, format)
	src.LogAction("DATA_EXPORTED", fmt.Sprintf("File: %s, Type: %s", in.Path, format))
	src.SendAlert(s.vault, src.LevelAll, "DATA EXPORT", "Vault data exported to "+in.Path)
	return map[string]any{"ok": true, "count": count}, nil
}

func hDataImport(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Format   string `json:"format"`
		Path     string `json:"path"`
		Password string `json:"password"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(in.Path)), ".")
	}
	before := len(s.vault.ItemRefs())
	prevSpace := s.vault.CurrentSpace
	var err error
	switch format {
	case "json":
		err = src.ImportFromJSON(s.vault, in.Path, in.Password)
	case "csv":
		err = src.ImportFromCSV(s.vault, in.Path)
	case "txt":
		err = src.ImportFromTXT(s.vault, in.Path)
	default:
		return nil, rpcErr("invalid", "Import format must be json, csv or txt.")
	}
	s.vault.CurrentSpace = prevSpace
	if err != nil {
		if data, rerr := os.ReadFile(s.vaultPath); rerr == nil {
			if v, derr := src.DecryptVault(data, s.password, 1); derr == nil {
				s.vault = v
			}
		}
		return nil, rpcErr("invalid", "Import failed: "+err.Error())
	}
	count := len(s.vault.ItemRefs()) - before
	if count > 0 {
		if err := s.save(fmt.Sprintf("Imported %d item(s)", count)); err != nil {
			return nil, err
		}
	}
	src.LogAction("DATA_IMPORTED", fmt.Sprintf("File: %s, Type: %s, Items: %d", in.Path, format, count))
	return s.withSnapshot(map[string]any{"count": count}), nil
}

func cleanupID(i int, iss src.CleanupIssue) string {
	return "c" + sha256Hex([]byte(fmt.Sprintf("%d|%s|%s", i, iss.Section, iss.Message)))[:11]
}

func hCleanupScan(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	issues := src.RunCleanup(s.vault)
	out := []map[string]any{}
	for i, iss := range issues {
		out = append(out, map[string]any{"id": cleanupID(i, iss), "title": iss.Message, "detail": iss.Section, "section": iss.Section, "severity": iss.Severity, "fix": iss.AutoFix && iss.RemoveFn != nil})
	}
	return map[string]any{"issues": out}, nil
}

func hCleanupApply(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, id := range in.IDs {
		want[id] = true
	}
	issues := src.RunCleanup(s.vault)
	fixed := 0
	for i := len(issues) - 1; i >= 0; i-- {
		iss := issues[i]
		if !want[cleanupID(i, iss)] || !iss.AutoFix || iss.RemoveFn == nil {
			continue
		}
		iss.RemoveFn(s.vault)
		fixed++
	}
	if fixed > 0 {
		if err := s.save(fmt.Sprintf("Cleanup fixed %d issue(s)", fixed)); err != nil {
			return nil, err
		}
		src.LogAction("VAULT_CLEANUP", fmt.Sprintf("Fixed %d/%d issues", fixed, len(issues)))
	}
	return s.withSnapshot(map[string]any{"fixed": fixed}), nil
}

func hAuditLog(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Action  string `json:"action"`
		Details string `json:"details"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	if !auditActionPattern.MatchString(in.Action) {
		return nil, rpcErr("invalid", "Audit actions are upper case words joined by underscores.")
	}
	details := in.Details
	if r := []rune(details); len(r) > 300 {
		details = string(r[:300])
	}
	src.LogAction(in.Action, details)
	return map[string]any{"ok": true}, nil
}

func hBridgeInfo(s *desktopServer, p json.RawMessage) (any, error) {
	return s.bridge.info(), nil
}

func hBridgeRotate(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	if err := s.bridge.rotate(); err != nil {
		return nil, err
	}
	src.LogAction("BRIDGE_TOKEN_ROTATED", "Browser extension pairing token rotated")
	return s.withSnapshot(map[string]any{"bridge": s.bridge.info()}), nil
}

func desktopSendMail(to, subject, title string, paragraphs []string, code string, tips []string) error {
	if dir := strings.TrimSpace(os.Getenv("APM_DESKTOP_MAIL_DIR")); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		body := "To: " + to + "\nSubject: " + subject + "\nCode: " + code + "\n\n" + title + "\n" + strings.Join(paragraphs, "\n") + "\n"
		name := fmt.Sprintf("%d.txt", time.Now().UnixNano())
		return os.WriteFile(filepath.Join(dir, name), []byte(body), 0600)
	}
	return sendAPMMail(to, subject, title, paragraphs, code, tips)
}
