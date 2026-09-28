package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/aaravmaloo/apm/internal/inject"
	src "github.com/aaravmaloo/apm/src"
	"golang.org/x/oauth2"
	"gopkg.in/gomail.v2"
)

func sendAPMMail(to, subject, title string, paragraphs []string, code string, tips []string) error {
	host, port, user, pass := apmSMTPConfig()
	m := gomail.NewMessage()
	m.SetHeader("From", user)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	setAPMEmailBody(m, title, paragraphs, code, tips)
	return gomail.NewDialer(host, port, user, pass).DialAndSend(m)
}

func openInBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", url).Start()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}

func validProvider(p string) bool {
	return p == "github" || p == "gdrive" || p == "dropbox"
}

func (s *desktopServer) prepareUpload(provider string) (string, func(), error) {
	return src.PrepareCloudUploadVaultPath(s.vault, s.password, s.vaultPath, provider)
}

func hSyncConnect(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Provider     string `json:"provider"`
		Mode         string `json:"mode"`
		Token        string `json:"token"`
		Repo         string `json:"repo"`
		Consent      bool   `json:"consent"`
		RetrievalKey string `json:"retrievalKey"`
		AppKey       string `json:"appKey"`
		AppSecret    string `json:"appSecret"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	provider := strings.ToLower(strings.TrimSpace(in.Provider))
	if !validProvider(provider) {
		return nil, rpcErr("invalid", "Choose GitHub, Google Drive or Dropbox.")
	}
	s.mu.Lock()
	if err := s.requireWritable(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	password := s.password
	s.mu.Unlock()
	ctx := context.Background()

	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	var cm src.CloudProvider
	var err error
	var token, creds []byte
	key := ""

	switch provider {
	case "github":
		tok := strings.TrimSpace(in.Token)
		repo := strings.TrimSpace(in.Repo)
		if tok == "" || !strings.Contains(repo, "/") {
			return nil, rpcErr("invalid", "Enter a GitHub token and a repository as owner/repo.")
		}
		gm, gerr := src.NewGitHubManager(ctx, tok)
		if gerr != nil {
			return nil, rpcErr("network", "GitHub error: "+gerr.Error())
		}
		gm.SetRepo(repo)
		cm = gm
		mode = "pat"
	case "gdrive":
		if mode == "" {
			mode = "apm_public"
		}
		if mode != "apm_public" && mode != "self_hosted" {
			return nil, rpcErr("invalid", "Mode must be apm_public or self_hosted.")
		}
		creds = src.GetDefaultCreds()
		if mode == "self_hosted" {
			token, err = src.PerformDriveAuth(creds)
			if err != nil {
				return nil, rpcErr("network", "Google sign in failed: "+err.Error())
			}
		} else {
			token = src.GetDefaultToken()
		}
		cm, err = getCloudManagerEx(ctx, &src.Vault{DriveSyncMode: mode, CloudToken: token, CloudCredentials: creds}, password, "gdrive")
	case "dropbox":
		if mode == "" {
			mode = "apm_public"
		}
		if mode == "self_hosted" {
			if strings.TrimSpace(in.AppKey) == "" || strings.TrimSpace(in.AppSecret) == "" {
				return nil, rpcErr("invalid", "Self-hosted Dropbox needs your app key and app secret.")
			}
			config := oauth2.Config{
				ClientID:     strings.TrimSpace(in.AppKey),
				ClientSecret: strings.TrimSpace(in.AppSecret),
				Endpoint:     oauth2.Endpoint{AuthURL: "https://www.dropbox.com/oauth2/authorize", TokenURL: "https://api.dropboxapi.com/oauth2/token"},
				RedirectURL:  "http://localhost:8080",
			}
			openInBrowser(config.AuthCodeURL("state-token", oauth2.AccessTypeOffline))
			token, err = src.PerformDropboxAuth(config)
			if err != nil {
				return nil, rpcErr("network", "Dropbox sign in failed: "+err.Error())
			}
		} else if mode == "apm_public" {
			token = src.GetDefaultDropboxToken()
		} else {
			return nil, rpcErr("invalid", "Mode must be apm_public or self_hosted.")
		}
		cm, err = getCloudManagerEx(ctx, &src.Vault{DropboxSyncMode: mode, DropboxToken: token}, password, "dropbox")
	}
	if err != nil {
		return nil, rpcErr("network", "Cloud error: "+err.Error())
	}
	if provider != "github" && in.Consent {
		key = strings.TrimSpace(in.RetrievalKey)
		if key == "" {
			key, err = src.GenerateRetrievalKey()
			if err != nil {
				return nil, err
			}
		}
	}

	s.mu.Lock()
	if err := s.requireWritable(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	path, cleanup, err := s.prepareUpload(provider)
	s.mu.Unlock()
	if err != nil {
		return nil, rpcErr("invalid", "Could not apply .apmignore: "+err.Error())
	}
	fileID, uerr := cm.UploadVault(path, key)
	cleanup()
	if uerr != nil {
		src.LogAction("CLOUD_INIT_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, uerr))
		return nil, rpcErr("network", "Upload failed: "+uerr.Error())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	v := s.vault
	switch provider {
	case "github":
		v.GitHubToken = strings.TrimSpace(in.Token)
		v.GitHubRepo = strings.TrimSpace(in.Repo)
		fileID = v.GitHubRepo
	case "gdrive":
		v.DriveSyncMode = mode
		v.CloudToken = token
		v.CloudCredentials = creds
		v.DriveKeyMetadataConsent = in.Consent
		v.RetrievalKey = key
		v.CloudFileID = fileID
		v.LastCloudProvider = "gdrive"
	case "dropbox":
		v.DropboxSyncMode = mode
		v.DropboxToken = token
		v.DropboxKeyMetadataConsent = in.Consent
		v.RetrievalKey = key
		v.DropboxFileID = fileID
		v.LastCloudProvider = "dropbox"
	}
	d := s.desktop()
	if d.SyncLast == nil {
		d.SyncLast = map[string]time.Time{}
	}
	d.SyncLast[provider] = time.Now()
	if d.SyncError != nil {
		delete(d.SyncError, provider)
	}
	if err := s.save("Connected " + providerLabel(provider)); err != nil {
		return nil, err
	}
	src.LogAction("CLOUD_INIT_SUCCESS", "Provider: "+provider)
	return s.withSnapshot(map[string]any{"provider": provider, "retrievalKey": key, "fileId": fileID}), nil
}

func providerLabel(p string) string {
	switch p {
	case "github":
		return "GitHub"
	case "gdrive":
		return "Google Drive"
	case "dropbox":
		return "Dropbox"
	}
	return p
}

func hSyncDisconnect(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Provider string `json:"provider"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	provider := strings.ToLower(strings.TrimSpace(in.Provider))
	if !validProvider(provider) {
		return nil, rpcErr("invalid", "Unknown provider.")
	}
	if !s.providerConnected(provider) {
		return s.withSnapshot(nil), nil
	}
	v := s.vault
	switch provider {
	case "github":
		v.GitHubToken = ""
		v.GitHubRepo = ""
	case "gdrive":
		v.CloudFileID = ""
		v.DriveSyncMode = ""
		v.DriveKeyMetadataConsent = false
		v.CloudCredentials = nil
		v.CloudToken = nil
		if v.LastCloudProvider == "gdrive" || v.DropboxFileID == "" {
			v.RetrievalKey = ""
		}
	case "dropbox":
		v.DropboxToken = nil
		v.DropboxSyncMode = ""
		v.DropboxKeyMetadataConsent = false
		v.DropboxFileID = ""
		if v.LastCloudProvider == "dropbox" || v.CloudFileID == "" {
			v.RetrievalKey = ""
		}
	default:
		return nil, rpcErr("invalid", "Unknown provider.")
	}
	if v.LastCloudProvider == provider {
		v.LastCloudProvider = ""
	}
	d := s.desktop()
	delete(d.SyncLast, provider)
	delete(d.SyncError, provider)
	delete(s.diffs, provider)
	if err := s.save("Disconnected " + providerLabel(provider)); err != nil {
		return nil, err
	}
	src.LogAction("CLOUD_RESET", "Provider: "+provider)
	return s.withSnapshot(nil), nil
}

type uploadJob struct {
	provider string
	cm       src.CloudProvider
	target   string
	path     string
	cleanup  func()
	err      error
}

func (s *desktopServer) syncNow(provider string, auto bool) (map[string]any, error) {
	s.mu.Lock()
	if !s.unlocked() {
		s.mu.Unlock()
		if auto {
			return nil, nil
		}
		return nil, rpcErr("locked", "The vault is locked.")
	}
	var providers []string
	if provider != "" {
		if !validProvider(provider) {
			s.mu.Unlock()
			return nil, rpcErr("invalid", "Unknown provider.")
		}
		if !s.providerConnected(provider) {
			s.mu.Unlock()
			return nil, rpcErr("invalid", providerLabel(provider)+" is not connected.")
		}
		providers = []string{provider}
	} else {
		for _, pr := range []string{"github", "gdrive", "dropbox"} {
			if s.providerConnected(pr) {
				providers = append(providers, pr)
			}
		}
	}
	if len(providers) == 0 {
		s.mu.Unlock()
		if auto {
			return nil, nil
		}
		return nil, rpcErr("invalid", "No sync provider is connected.")
	}
	vc := *s.vault
	var jobs []*uploadJob
	for _, pr := range providers {
		job := &uploadJob{provider: pr, cleanup: func() {}}
		job.cm, job.err = getCloudManagerEx(context.Background(), &vc, s.password, pr)
		switch pr {
		case "github":
			job.target = vc.GitHubRepo
		case "gdrive":
			job.target = vc.CloudFileID
		case "dropbox":
			job.target = vc.DropboxFileID
		}
		if job.err == nil {
			job.path, job.cleanup, job.err = s.prepareUpload(pr)
		}
		jobs = append(jobs, job)
	}
	s.mu.Unlock()

	for _, job := range jobs {
		if job.err == nil {
			job.err = job.cm.SyncVault(job.path, job.target)
		}
		job.cleanup()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	errs := map[string]string{}
	if !s.unlocked() {
		return map[string]any{"count": 0, "errors": errs}, nil
	}
	d := s.desktop()
	if d.SyncLast == nil {
		d.SyncLast = map[string]time.Time{}
	}
	if d.SyncError == nil {
		d.SyncError = map[string]string{}
	}
	action := "CLOUD_SYNC"
	if auto {
		action = "CLOUD_AUTOSYNC"
	}
	for _, job := range jobs {
		if job.err != nil {
			errs[job.provider] = job.err.Error()
			d.SyncError[job.provider] = job.err.Error()
			src.LogAction(action+"_FAILED", fmt.Sprintf("Provider: %s, Error: %v", job.provider, job.err))
			continue
		}
		count++
		d.SyncLast[job.provider] = time.Now()
		delete(d.SyncError, job.provider)
		src.LogAction(action+"_SUCCESS", "Provider: "+job.provider)
	}
	if !s.isReadonly() {
		_ = s.saveQuiet()
	}
	res := map[string]any{"count": count, "errors": errs}
	if auto {
		s.emit("vault.changed", map[string]any{"snapshot": s.snapshot()})
		return res, nil
	}
	return s.withSnapshot(res), nil
}

func hSyncNow(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Provider string `json:"provider"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	res, err := s.syncNow(strings.ToLower(strings.TrimSpace(in.Provider)), false)
	if err != nil {
		return nil, err
	}
	if c, _ := res["count"].(int); c == 0 {
		if errs, _ := res["errors"].(map[string]string); len(errs) > 0 {
			var parts []string
			for k, v := range errs {
				parts = append(parts, providerLabel(k)+": "+v)
			}
			sort.Strings(parts)
			return nil, rpcErrData("network", "Sync failed. "+strings.Join(parts, "; "), map[string]any{"errors": errs})
		}
	}
	return res, nil
}

func diffTypeID(itemType string) string {
	if spec, ok := src.ItemTypeByCategory(resultTypeToHistoryCategory(itemType)); ok {
		return spec.ID
	}
	return itemType
}

func diffView(changes []src.VaultDiffChange) []map[string]any {
	out := []map[string]any{}
	for i, c := range changes {
		fields := c.ChangedFields
		if fields == nil {
			fields = []string{}
		}
		space := c.Space
		if strings.EqualFold(space, "default") {
			space = ""
		}
		out = append(out, map[string]any{"index": i, "kind": c.Kind, "type": diffTypeID(c.ItemType), "identifier": c.Identifier, "space": space, "fields": fields})
	}
	return out
}

func hSyncDiff(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Provider string `json:"provider"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err := s.requireUnlocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	provider := strings.ToLower(strings.TrimSpace(in.Provider))
	if provider == "" {
		provider = resolveCloudDiffProvider(s.vault, nil)
	}
	if !validProvider(provider) || !s.providerConnected(provider) {
		s.mu.Unlock()
		return nil, rpcErr("invalid", "Connect a sync provider first.")
	}
	vc := *s.vault
	password := s.password
	s.mu.Unlock()
	data, err := downloadConfiguredCloudVault(context.Background(), &vc, password, provider)
	if err != nil {
		return nil, rpcErr("network", "Could not download the cloud vault: "+err.Error())
	}
	remote, err := src.DecryptVault(data, password, 1)
	if err != nil {
		return nil, rpcErr("wrong_password", "The cloud vault uses a different master password.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	changes := src.DiffVaultEntries(s.vault, remote)
	s.diffs[provider] = changes
	return map[string]any{"provider": provider, "changes": diffView(changes)}, nil
}

func hSyncApply(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Provider string `json:"provider"`
		Selected []int  `json:"selected"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	provider := strings.ToLower(strings.TrimSpace(in.Provider))
	s.mu.Lock()
	if err := s.requireWritable(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	changes, ok := s.diffs[provider]
	if !ok {
		s.mu.Unlock()
		return nil, rpcErr("invalid", "Compare with the cloud first.")
	}
	for _, i := range in.Selected {
		if i < 0 || i >= len(changes) {
			s.mu.Unlock()
			return nil, rpcErr("invalid", "That change is no longer available. Compare again.")
		}
	}
	if len(in.Selected) > 0 {
		if err := src.ApplyVaultDiffSelection(s.vault, changes, in.Selected); err != nil {
			s.mu.Unlock()
			return nil, rpcErr("invalid", "Merge failed: "+err.Error())
		}
		note := fmt.Sprintf("Merged %d cloud change(s) from %s", len(in.Selected), providerLabel(provider))
		if err := s.save(note); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		src.LogAction("CLOUD_MERGE", note)
	}
	delete(s.diffs, provider)
	s.mu.Unlock()
	res, err := s.syncNow(provider, false)
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := s.withSnapshot(map[string]any{"applied": len(in.Selected), "uploadError": err.Error()})
		return out, nil
	}
	res["applied"] = len(in.Selected)
	return res, nil
}

func hSyncIgnore(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Text string `json:"text"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if _, err := src.ParseIgnoreConfig(in.Text); err != nil {
		return nil, rpcErr("invalid", "The .apmignore rules have an error: "+err.Error())
	}
	_, path := s.ignoreInfo()
	if err := os.WriteFile(path, []byte(in.Text), 0600); err != nil {
		return nil, err
	}
	src.LogAction("APMIGNORE_UPDATED", path)
	return s.withSnapshot(nil), nil
}

func hSyncAuto(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		On bool `json:"on"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	s.desktop().SyncAuto = in.On
	if err := s.save("Auto sync turned " + map[bool]string{true: "on", false: "off"}[in.On]); err != nil {
		return nil, err
	}
	src.LogAction("CLOUD_SETTINGS", fmt.Sprintf("Auto sync: %v", in.On))
	return s.withSnapshot(nil), nil
}

func hSyncRestore(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Provider  string `json:"provider"`
		Key       string `json:"key"`
		Token     string `json:"token"`
		Repo      string `json:"repo"`
		Mode      string `json:"mode"`
		Password  string `json:"password"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	provider := strings.ToLower(strings.TrimSpace(in.Provider))
	if !validProvider(provider) {
		return nil, rpcErr("invalid", "Choose GitHub, Google Drive or Dropbox.")
	}
	s.mu.Lock()
	if s.unlocked() {
		s.mu.Unlock()
		return nil, rpcErr("invalid", "Lock the vault before restoring another copy over it.")
	}
	if src.VaultExists(s.vaultPath) && !in.Overwrite {
		s.mu.Unlock()
		return nil, rpcErr("vault_exists", "A vault already exists here. Confirm to replace it; the current file is kept as a backup.")
	}
	s.mu.Unlock()

	ctx := context.Background()
	var data []byte
	var err error
	switch provider {
	case "github":
		repo := strings.TrimSpace(in.Repo)
		if repo == "" {
			repo = strings.TrimSpace(in.Key)
		}
		if strings.TrimSpace(in.Token) == "" || repo == "" {
			return nil, rpcErr("invalid", "Enter the GitHub token and repository.")
		}
		gm, gerr := src.NewGitHubManager(ctx, strings.TrimSpace(in.Token))
		if gerr != nil {
			return nil, rpcErr("network", gerr.Error())
		}
		data, err = gm.DownloadVault(repo)
		in.Repo = repo
	case "gdrive", "dropbox":
		key := strings.TrimSpace(in.Key)
		if key == "" {
			return nil, rpcErr("invalid", "Enter your retrieval key or file id.")
		}
		var cp src.CloudProvider
		var cerr error
		if provider == "gdrive" {
			if strings.EqualFold(in.Mode, "self_hosted") {
				tok, aerr := src.PerformDriveAuth(src.GetDefaultCreds())
				if aerr != nil {
					return nil, rpcErr("network", "Google sign in failed: "+aerr.Error())
				}
				cp, cerr = src.GetCloudProvider("gdrive", ctx, src.GetDefaultCreds(), tok, "self_hosted")
			} else {
				cp, cerr = src.GetCloudProvider("gdrive", ctx, nil, nil, "apm_public")
			}
		} else {
			mode := "apm_public"
			if strings.TrimSpace(in.Token) != "" {
				mode = "self_hosted"
			}
			cp, cerr = src.GetCloudProvider("dropbox", ctx, nil, []byte(strings.TrimSpace(in.Token)), mode)
		}
		if cerr != nil {
			return nil, rpcErr("network", "Cloud error: "+cerr.Error())
		}
		fileID, rerr := cp.ResolveKeyToID(key)
		if rerr != nil {
			src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, rerr))
			return nil, rpcErr("not_found", "No vault matches that key: "+rerr.Error())
		}
		data, err = cp.DownloadVault(fileID)
	}
	if err != nil {
		src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, err))
		return nil, rpcErr("network", "Download failed: "+err.Error())
	}
	v, derr := src.DecryptVault(data, in.Password, 1)
	if derr != nil {
		return nil, rpcErr("wrong_password", "That master password does not open the downloaded vault.")
	}
	if provider == "github" {
		v.GitHubToken = strings.TrimSpace(in.Token)
		v.GitHubRepo = strings.TrimSpace(in.Repo)
		if data, err = src.EncryptVault(v, in.Password); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	backup := ""
	if src.VaultExists(s.vaultPath) {
		if old, rerr := os.ReadFile(s.vaultPath); rerr == nil {
			backup = fmt.Sprintf("%s.backup.%s", s.vaultPath, time.Now().Format("20060102-150405"))
			if werr := os.WriteFile(backup, old, 0600); werr != nil {
				return nil, werr
			}
		}
	}
	if err := s.writeVault(data, true, "Restored from "+providerLabel(provider)); err != nil {
		return nil, err
	}
	src.LogAction("CLOUD_DOWNLOAD_SUCCESS", "Provider: "+provider)
	res := s.finishUnlock(in.Password, v, "cloud restore", true)
	res["backup"] = backup
	return res, nil
}

var injectFieldByType = map[string]string{
	"password": "password", "totp": "secret", "token": "token", "note": "content", "apikey": "key", "ssh_key": "private_key",
	"wifi": "password", "recovery": "codes", "certificate": "private_key", "cloud": "secret_key", "docker": "token", "ssh_config": "private_key",
}

func hInjectPreview(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	env := []map[string]any{}
	unsupported := []string{}
	var names []string
	for _, id := range in.IDs {
		ref, ok := s.vault.FindItem(id)
		if !ok {
			continue
		}
		field, ok := injectFieldByType[ref.Spec.ID]
		if !ok {
			unsupported = append(unsupported, ref.Title)
			continue
		}
		f := s.vault.ItemRecordFields(ref)
		value := ""
		switch t := f[field].(type) {
		case []string:
			value = strings.Join(t, "\n")
		default:
			value = toStr(t)
		}
		names = append(names, ref.Title)
		env = append(env, map[string]any{"name": inject.ToEnvVarName(ref.Title), "entry": ref.Title, "type": ref.Spec.ID, "space": ref.Space, "value_masked": maskSecret(value)})
	}
	command := ""
	if len(names) > 0 {
		quoted := strings.Join(names, ",")
		command = "pm inject --inject \"" + strings.ReplaceAll(quoted, "\"", "\\\"") + "\""
	}
	return map[string]any{"env": env, "command": command, "unsupported": unsupported}, nil
}
