package apm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func PeekSession() (*Session, error) {
	data, err := os.ReadFile(getSessionFile())
	if err != nil {
		return nil, errors.New("no active session")
	}
	session, _, err := decryptSessionData(data)
	if err != nil {
		return nil, errors.New("no active session")
	}
	now := time.Now()
	if session.Expired(now) {
		return nil, errors.New("session expired")
	}
	if session.InactivityTimeout > 0 && now.Sub(session.LastUsed) > session.InactivityTimeout {
		return nil, errors.New("session locked due to inactivity")
	}
	if session.Slept() {
		return nil, errors.New("session locked because the computer slept")
	}
	session.MasterPassword = ""
	return &session, nil
}

func PurgeLGitForVault(vaultPath string) (int, error) {
	commits, err := GetLGitCommits(0)
	if err != nil {
		return 0, err
	}
	target := filepath.Clean(vaultPath)
	var kept []LGitCommit
	removed := 0
	for _, c := range commits {
		if filepath.Clean(c.VaultPath) == target {
			if c.SnapshotFile != "" {
				_ = os.Remove(c.SnapshotFile)
			}
			removed++
			continue
		}
		kept = append(kept, c)
	}
	if removed == 0 {
		return 0, nil
	}
	if err := rewriteLGitChain(kept); err != nil {
		return removed, err
	}
	notes := loadLGitNotes()
	for _, c := range commits {
		if filepath.Clean(c.VaultPath) == target {
			delete(notes, c.ID)
		}
	}
	_ = saveLGitNotes(notes)
	return removed, nil
}

func lgitNotesFile() string {
	apmDir, _ := getAPMConfigDir()
	return filepath.Join(apmDir, "lgit_notes.json")
}

type lgitNote struct {
	Note string    `json:"note"`
	At   time.Time `json:"at"`
}

func loadLGitNotes() map[string]lgitNote {
	out := map[string]lgitNote{}
	data, err := os.ReadFile(lgitNotesFile())
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

func saveLGitNotes(notes map[string]lgitNote) error {
	if len(notes) > 1000 {
		type kv struct {
			id string
			at time.Time
		}
		list := make([]kv, 0, len(notes))
		for id, n := range notes {
			list = append(list, kv{id, n.At})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].at.After(list[j].at) })
		for _, e := range list[1000:] {
			delete(notes, e.id)
		}
	}
	data, err := json.Marshal(notes)
	if err != nil {
		return err
	}
	return os.WriteFile(lgitNotesFile(), data, 0600)
}

func SetLGitNote(commitID, note string) error {
	if commitID == "" || note == "" {
		return nil
	}
	notes := loadLGitNotes()
	notes[commitID] = lgitNote{Note: note, At: time.Now()}
	return saveLGitNotes(notes)
}

func LGitNotes() map[string]string {
	out := map[string]string{}
	for id, n := range loadLGitNotes() {
		out[id] = n.Note
	}
	return out
}
