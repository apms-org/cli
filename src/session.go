package apm

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sessionEnvelopeVersion = 1
	sessionKeyFileName     = "session.key"
)

type Session struct {
	MasterPassword    string        `json:"master_password"`
	ReadOnly          bool          `json:"readonly"`
	Expiry            time.Time     `json:"expiry"`
	LastUsed          time.Time     `json:"last_used"`
	InactivityTimeout time.Duration `json:"inactivity_timeout"`
	// LockOnSleep ends the session once the computer has slept. SleepMark is
	// the platform's sleep counter when the session started.
	LockOnSleep bool  `json:"lock_on_sleep,omitempty"`
	SleepMark   int64 `json:"sleep_mark,omitempty"`
}

// SleepLockSupported reports whether pm can tell that the computer slept.
func SleepLockSupported() bool {
	_, ok := sleepMark()
	return ok
}

// Slept reports whether the session should end because the computer slept.
func (s Session) Slept() bool {
	return s.LockOnSleep && sleptSince(s.SleepMark)
}

// Expired reports whether the session has passed its maximum length. A zero
// Expiry means the session has no maximum length.
func (s Session) Expired(now time.Time) bool {
	return !s.Expiry.IsZero() && now.After(s.Expiry)
}

type sessionEnvelope struct {
	Version    int    `json:"version"`
	Ciphertext string `json:"ciphertext"`
}

func getSessionFile() string {
	sessionID := os.Getenv("APM_SESSION_ID")
	if sessionID == "" {
		return filepath.Join(os.TempDir(), "pm_session_global.json")
	}

	sanitizedID := ""
	for _, char := range sessionID {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			sanitizedID += string(char)
		}
	}
	if sanitizedID == "" {
		sanitizedID = "unknown"
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("pm_session_%s.json", sanitizedID))
}

func CreateSession(password string, duration time.Duration, readonly bool, inactivity time.Duration) error {
	return CreateLockingSession(password, duration, readonly, inactivity, false)
}

// CreateLockingSession is CreateSession that can also end when the computer
// sleeps. A zero duration or inactivity means no limit.
func CreateLockingSession(password string, duration time.Duration, readonly bool, inactivity time.Duration, lockOnSleep bool) error {
	session := Session{
		MasterPassword:    password,
		ReadOnly:          readonly,
		LastUsed:          time.Now(),
		InactivityTimeout: inactivity,
	}
	if duration > 0 {
		session.Expiry = time.Now().Add(duration)
	}
	if lockOnSleep {
		if mark, ok := sleepMark(); ok {
			session.LockOnSleep = true
			session.SleepMark = mark
		}
	}

	data, err := encryptSessionData(session)
	if err != nil {
		return err
	}

	sessionFile := getSessionFile()
	if err := os.WriteFile(sessionFile, data, 0600); err != nil {
		return err
	}

	if duration > 0 {
		go func() {
			time.Sleep(duration)
			_ = os.Remove(sessionFile)
		}()
	}

	return nil
}



func GetSession() (*Session, error) {
	sessionFile := getSessionFile()
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		return nil, errors.New("no active session")
	}

	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, err
	}

	session, _, err := decryptSessionData(data)
	if err != nil {
		_ = os.Remove(sessionFile)
		return nil, errors.New("no active session")
	}

	now := time.Now()
	if session.Expired(now) {
		_ = os.Remove(sessionFile)
		return nil, errors.New("session expired")
	}

	if session.InactivityTimeout > 0 && now.Sub(session.LastUsed) > session.InactivityTimeout {
		_ = os.Remove(sessionFile)
		return nil, errors.New("session locked due to inactivity")
	}

	if session.Slept() {
		_ = os.Remove(sessionFile)
		return nil, errors.New("session locked because the computer slept")
	}

	session.LastUsed = now
	if updatedData, err := encryptSessionData(session); err == nil {
		_ = os.WriteFile(sessionFile, updatedData, 0600)
	}

	return &session, nil
}

func KillSession() error {
	return os.Remove(getSessionFile())
}

func encryptSessionData(session Session) ([]byte, error) {
	plain, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	key, err := getSessionKey()
	if err != nil {
		return nil, err
	}
	encrypted, err := EncryptData(plain, key)
	if err != nil {
		return nil, err
	}
	env := sessionEnvelope{
		Version:    sessionEnvelopeVersion,
		Ciphertext: base64.StdEncoding.EncodeToString(encrypted),
	}
	return json.Marshal(env)
}

func decryptSessionData(data []byte) (Session, bool, error) {
	var env sessionEnvelope
	if err := json.Unmarshal(data, &env); err == nil && env.Version == sessionEnvelopeVersion && strings.TrimSpace(env.Ciphertext) != "" {
		blob, err := base64.StdEncoding.DecodeString(env.Ciphertext)
		if err != nil {
			return Session{}, true, err
		}
		key, err := getSessionKey()
		if err != nil {
			return Session{}, true, err
		}
		plain, err := DecryptData(blob, key)
		if err != nil {
			return Session{}, true, err
		}
		var session Session
		if err := json.Unmarshal(plain, &session); err != nil {
			return Session{}, true, err
		}
		return session, true, nil
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, false, err
	}
	return session, false, nil
}

func getSessionKey() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	apmDir := filepath.Join(configDir, "apm")
	if err := os.MkdirAll(apmDir, 0700); err != nil {
		return "", err
	}
	keyPath := filepath.Join(apmDir, sessionKeyFileName)
	if raw, err := os.ReadFile(keyPath); err == nil {
		key := strings.TrimSpace(string(raw))
		if key != "" {
			if decoded, err := base64.StdEncoding.DecodeString(key); err == nil && len(decoded) == 32 {
				return key, nil
			}
			// Key is corrupted (wrong length or invalid base64).
			return "", fmt.Errorf("session key file %s contains invalid key data", keyPath)
		}
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	key := base64.StdEncoding.EncodeToString(secret)
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		return "", err
	}
	return key, nil
}
