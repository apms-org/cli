package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type AccessLog struct {
	Timestamp  int64
	DeviceHash string
	Action     string
}

func GetDeviceHash() string {
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}

	raw := fmt.Sprintf("%s-%s", host, user)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func LogAccess(action string) {
	entry := fmt.Sprintf("%d|%s|%s\n", time.Now().Unix(), GetDeviceHash(), action)

	path := filepath.Join(apmStateDir(), "apm_audit.log")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(entry)
	}
}

func CheckAnomalies(vault *Vault) []string {

	var alerts []string

	h := time.Now().Hour()
	if h >= 2 && h <= 5 {
		alerts = append(alerts, fmt.Sprintf("Unusual activity time (%02d:00)", h))
	}

	return alerts
}
