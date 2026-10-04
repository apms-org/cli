package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	src "github.com/aaravmaloo/apm/src"
)

// Import, compare and export for the desktop app. A preview parses the file
// once and keeps it in memory behind a token until it is applied, discarded
// or the vault locks, so decrypting and planning never happen twice.

type pendingTransfer struct {
	set      *src.TransferSet
	fileName string
	created  time.Time
}

const maxTransferBytes = 512 << 20

type transferSourceParams struct {
	Path       string `json:"path"`
	Name       string `json:"name"`
	Data       string `json:"data"`
	Password   string `json:"password"`
	From       string `json:"from"`
	Space      string `json:"space"`
	KeepSpaces *bool  `json:"keepSpaces"`
}

func readTransferSource(in transferSourceParams) (string, []byte, error) {
	if p := strings.TrimSpace(in.Path); p != "" {
		p = filepath.Clean(p)
		st, err := os.Stat(p)
		if err != nil {
			return "", nil, rpcErr("not_found", "APM cannot open "+filepath.Base(p)+".")
		}
		if st.IsDir() {
			return "", nil, rpcErr("invalid", filepath.Base(p)+" is a folder. Choose the export file inside it.")
		}
		if st.Size() > maxTransferBytes {
			return "", nil, rpcErr("invalid", "The file is larger than 512 MB.")
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return "", nil, rpcErr("not_found", "APM cannot read "+filepath.Base(p)+": "+err.Error())
		}
		return filepath.Base(p), data, nil
	}
	if in.Data == "" {
		return "", nil, rpcErr("invalid", "Choose a file to import.")
	}
	data, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil {
		return "", nil, rpcErr("invalid", "The file data is not valid base64.")
	}
	name := filepath.Base(strings.TrimSpace(in.Name))
	if name == "." || name == "" {
		name = "import"
	}
	return name, data, nil
}

func transferRPCError(err error, set *src.TransferSet) error {
	var te *src.TransferError
	if errors.As(err, &te) {
		data := map[string]any{}
		if set != nil {
			data["formatLabel"] = set.FormatLabel
			data["vendor"] = set.Vendor
		}
		return rpcErrData(te.Code, te.Message, data)
	}
	return rpcErr("invalid", "The file could not be read: "+err.Error())
}

func (s *desktopServer) parseTransfer(in transferSourceParams) (string, *src.TransferSet, error) {
	name, data, err := readTransferSource(in)
	if err != nil {
		return "", nil, err
	}
	set, err := src.ParseTransfer(name, data, in.Password, in.From)
	if err != nil {
		return name, nil, transferRPCError(err, set)
	}
	return name, set, nil
}

func (s *desktopServer) keepTransfer(name string, set *src.TransferSet) string {
	if s.transfers == nil {
		s.transfers = map[string]*pendingTransfer{}
	}
	if len(s.transfers) >= 4 {
		oldest := ""
		for k, t := range s.transfers {
			if oldest == "" || t.created.Before(s.transfers[oldest].created) {
				oldest = k
			}
		}
		delete(s.transfers, oldest)
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	token := "x" + base64.RawURLEncoding.EncodeToString(b)
	s.transfers[token] = &pendingTransfer{set: set, fileName: name, created: time.Now()}
	return token
}

func (s *desktopServer) pendingTransfer(token string) (*pendingTransfer, error) {
	t, ok := s.transfers[strings.TrimSpace(token)]
	if !ok {
		return nil, rpcErr("expired", "That import is no longer open. Choose the file again.")
	}
	return t, nil
}

func defaultKeepSpaces(set *src.TransferSet, want *bool) bool {
	if want != nil {
		return *want
	}
	return set.Vendor == "apm"
}

func transferHeader(token, name string, set *src.TransferSet) map[string]any {
	warnings := set.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	return map[string]any{"token": token, "fileName": name, "format": set.Format, "formatLabel": set.FormatLabel, "vendor": set.Vendor, "encrypted": set.Encrypted, "warnings": warnings}
}

func hTransferFormats(s *desktopServer, p json.RawMessage) (any, error) {
	formats := []map[string]any{}
	for _, f := range src.TransferFormats() {
		formats = append(formats, map[string]any{"id": f.ID, "label": f.Label, "vendor": f.Vendor, "ext": f.Ext, "help": f.Help})
	}
	exporters := []map[string]any{}
	for _, e := range src.TransferExporters() {
		exporters = append(exporters, map[string]any{"id": e.ID, "label": e.Label, "vendor": e.Vendor, "ext": e.Ext, "help": e.Help, "passkeys": e.Passkeys, "encryption": e.Encryption, "files": e.Files, "secrets": e.Secrets, "types": e.Types})
	}
	return map[string]any{"formats": formats, "exporters": exporters}, nil
}

func (s *desktopServer) previewTransfer(p json.RawMessage, compare bool) (any, error) {
	var in transferSourceParams
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	err := s.requireUnlocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	name, set, err := s.parseTransfer(in)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	token := s.keepTransfer(name, set)
	res := transferHeader(token, name, set)
	opt := src.PlanOptions{Space: normalizeSpaceParam(in.Space), KeepSpaces: defaultKeepSpaces(set, in.KeepSpaces)}
	if compare {
		opt.KeepSpaces = true
		plan, only := src.CompareTransfer(s.vault, set, opt)
		res["plan"] = plan
		res["vaultOnly"] = only
		return res, nil
	}
	res["plan"] = src.PlanTransfer(s.vault, set, opt)
	return res, nil
}

func hTransferPreview(s *desktopServer, p json.RawMessage) (any, error) {
	return s.previewTransfer(p, false)
}

func hTransferCompare(s *desktopServer, p json.RawMessage) (any, error) {
	return s.previewTransfer(p, true)
}

type transferPlanParams struct {
	Token      string            `json:"token"`
	Space      string            `json:"space"`
	KeepSpaces *bool             `json:"keepSpaces"`
	Decisions  map[string]string `json:"decisions"`
}

func hTransferPlan(s *desktopServer, p json.RawMessage) (any, error) {
	var in transferPlanParams
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	t, err := s.pendingTransfer(in.Token)
	if err != nil {
		return nil, err
	}
	opt := src.PlanOptions{Space: normalizeSpaceParam(in.Space), KeepSpaces: defaultKeepSpaces(t.set, in.KeepSpaces)}
	return map[string]any{"plan": src.PlanTransfer(s.vault, t.set, opt)}, nil
}

func hTransferApply(s *desktopServer, p json.RawMessage) (any, error) {
	var in transferPlanParams
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	t, err := s.pendingTransfer(in.Token)
	if err != nil {
		return nil, err
	}
	decisions := map[int]string{}
	for k, v := range in.Decisions {
		if i, err := strconv.Atoi(k); err == nil {
			decisions[i] = v
		}
	}
	opt := src.PlanOptions{Space: normalizeSpaceParam(in.Space), KeepSpaces: defaultKeepSpaces(t.set, in.KeepSpaces)}
	res, _ := src.ApplyTransfer(s.vault, t.set, opt, decisions)
	if res.Changed() > 0 {
		note := importNote(t.fileName, t.set, res)
		if err := s.save(note); err != nil {
			return nil, err
		}
		src.LogAction("DATA_IMPORTED", fmt.Sprintf("File: %s, Format: %s, Added: %d, Merged: %d, Replaced: %d, Skipped: %d, Passkeys: %d", t.fileName, t.set.Format, res.Added, res.Merged, res.Replaced, res.Skipped, res.PasskeysAdded))
	}
	delete(s.transfers, strings.TrimSpace(in.Token))
	return s.withSnapshot(map[string]any{"result": res}), nil
}

func importNote(name string, set *src.TransferSet, res src.TransferResult) string {
	parts := []string{}
	if res.Added > 0 {
		parts = append(parts, fmt.Sprintf("%d added", res.Added))
	}
	if res.Merged > 0 {
		parts = append(parts, fmt.Sprintf("%d merged", res.Merged))
	}
	if res.Replaced > 0 {
		parts = append(parts, fmt.Sprintf("%d replaced", res.Replaced))
	}
	if res.PasskeysAdded > 0 {
		parts = append(parts, fmt.Sprintf("%d passkeys", res.PasskeysAdded))
	}
	return "Imported " + name + " (" + set.FormatLabel + "): " + strings.Join(parts, ", ")
}

func hTransferDiscard(s *desktopServer, p json.RawMessage) (any, error) {
	var in transferPlanParams
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	delete(s.transfers, strings.TrimSpace(in.Token))
	return map[string]any{"ok": true}, nil
}

type transferExportParams struct {
	Format   string   `json:"format"`
	Path     string   `json:"path"`
	IDs      []string `json:"ids"`
	Types    []string `json:"types"`
	Spaces   []string `json:"spaces"`
	Passkeys *bool    `json:"passkeys"`
	Files    bool     `json:"files"`
	Secrets  *bool    `json:"secrets"`
	Password string   `json:"password"`
}

func (in transferExportParams) selection() (src.ExportSelection, src.ExportOptions) {
	sel := src.ExportSelection{IDs: in.IDs, Types: in.Types, Spaces: in.Spaces, Passkeys: in.Passkeys == nil || *in.Passkeys, Files: in.Files}
	opt := src.ExportOptions{Password: in.Password, Secrets: in.Secrets == nil || *in.Secrets}
	return sel, opt
}

func hTransferExportPreview(s *desktopServer, p json.RawMessage) (any, error) {
	var in transferExportParams
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	sel, opt := in.selection()
	_, _, sum, err := s.vault.PlanExport(in.Format, sel, opt)
	if err != nil {
		return nil, transferRPCError(err, nil)
	}
	return map[string]any{"summary": sum}, nil
}

func hTransferExport(s *desktopServer, p json.RawMessage) (any, error) {
	var in transferExportParams
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Path) == "" {
		return nil, rpcErr("invalid", "Choose where to save the export.")
	}
	s.mu.Lock()
	if err := s.requireUnlocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	sel, opt := in.selection()
	opt.VaultName = s.vaultName()
	ex, items, sum, err := s.vault.PlanExport(in.Format, sel, opt)
	s.mu.Unlock()
	if err != nil {
		return nil, transferRPCError(err, nil)
	}
	if len(items) == 0 {
		return nil, rpcErr("empty", "Nothing to export. The selection has no items "+ex.Label+" can hold.")
	}
	opt.Created = time.Now()
	if !ex.Encryption {
		opt.Password = ""
	}
	data, err := ex.Write(items, opt)
	if err != nil {
		return nil, rpcErr("internal", "The export could not be written: "+err.Error())
	}
	path := filepath.Clean(in.Path)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, rpcErr("invalid", "APM cannot write "+filepath.Base(path)+": "+err.Error())
	}
	_ = os.Chmod(path, 0600)
	s.mu.Lock()
	defer s.mu.Unlock()
	src.LogAction("DATA_EXPORTED", fmt.Sprintf("File: %s, Format: %s, Items: %d, Passkeys: %d, Encrypted: %t", path, ex.ID, sum.Items, sum.Passkeys, sum.Encrypted))
	if s.vault != nil {
		src.SendAlert(s.vault, src.LevelAll, "DATA EXPORT", fmt.Sprintf("%d items exported to %s (%s)", sum.Items, path, ex.Label))
	}
	return map[string]any{"ok": true, "summary": sum, "path": path, "bytes": len(data)}, nil
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
