//go:build !darwin

package touchid

// IsAvailable returns false on non-macOS platforms.
func IsAvailable() bool { return false }

// IsConfigured returns false on non-macOS platforms.
func IsConfigured() bool { return false }

// Setup returns ErrNotAvailable on non-macOS platforms.
func Setup(masterPassword string) error { return ErrNotAvailable }

// GetPassword returns ErrNotAvailable on non-macOS platforms.
func GetPassword() (string, error) { return "", ErrNotAvailable }

// Remove returns ErrNotAvailable on non-macOS platforms.
func Remove() error { return ErrNotAvailable }

// Store returns ErrNotAvailable on non-macOS platforms.
func Store(masterPassword string) error { return ErrNotAvailable }

// ReadPassword returns ErrNotAvailable on non-macOS platforms.
func ReadPassword() (string, error) { return "", ErrNotAvailable }

// Delete returns ErrNotAvailable on non-macOS platforms.
func Delete() error { return ErrNotAvailable }

// Status returns a status map indicating Touch ID is not available.
func Status() map[string]interface{} {
	return map[string]interface{}{
		"available":   false,
		"configured":  false,
		"platform":    "unknown",
	}
}

// StatusText returns a human-readable string for non-macOS.
func StatusText() string {
	return "Touch ID is only available on macOS"
}

// Authenticate returns ErrNotAvailable on non-macOS platforms.
func Authenticate(reason string) error { return ErrNotAvailable }
