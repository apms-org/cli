package apm

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func uniqueSessionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func TestSessionLifecycle(t *testing.T) {
	t.Setenv("APM_SESSION_ID", uniqueSessionID("lifecycle"))
	_ = KillSession()
	defer KillSession()

	if err := CreateSession("testpassword", 2*time.Second, false, 1*time.Second); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	sess, err := GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sess.MasterPassword != "testpassword" {
		t.Fatalf("unexpected password in session: %q", sess.MasterPassword)
	}
	if sess.ReadOnly {
		t.Fatal("expected ReadOnly=false")
	}

	if err := KillSession(); err != nil {
		t.Fatalf("KillSession failed: %v", err)
	}

	if _, err := GetSession(); err == nil || err.Error() != "no active session" {
		t.Fatalf("expected 'no active session', got %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	t.Setenv("APM_SESSION_ID", uniqueSessionID("expiry"))
	_ = KillSession()
	defer KillSession()

	if err := CreateSession("pass", 100*time.Millisecond, false, 0); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	time.Sleep(250 * time.Millisecond)

	_, err := GetSession()
	if err == nil {
		t.Fatal("expected expiry error")
	}
	if err.Error() != "session expired" && err.Error() != "no active session" {
		t.Fatalf("expected expiry-related error, got %v", err)
	}
}

func TestSessionInactivityLock(t *testing.T) {
	t.Setenv("APM_SESSION_ID", uniqueSessionID("inactivity"))
	_ = KillSession()
	defer KillSession()

	if err := CreateSession("pass", 2*time.Second, false, 100*time.Millisecond); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	_, err := GetSession()
	if err == nil {
		t.Fatal("expected inactivity lock error")
	}
	if err.Error() != "session locked due to inactivity" && err.Error() != "no active session" {
		t.Fatalf("expected inactivity-related error, got %v", err)
	}
}

func TestSessionWithoutMaximum(t *testing.T) {
	t.Setenv("APM_SESSION_ID", uniqueSessionID("nolimit"))
	_ = KillSession()
	defer KillSession()

	if err := CreateSession("pass", 0, false, 0); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	sess, err := GetSession()
	if err != nil {
		t.Fatalf("a session with no maximum expired at once: %v", err)
	}
	if !sess.Expiry.IsZero() || sess.Expired(time.Now().Add(24*time.Hour)) {
		t.Fatalf("expected no expiry, got %v", sess.Expiry)
	}
	if peek, err := PeekSession(); err != nil || peek == nil {
		t.Fatalf("PeekSession: %v", err)
	}
}

func TestSessionEndsAfterSleep(t *testing.T) {
	if !SleepLockSupported() {
		t.Skip("this platform cannot tell that the computer slept")
	}
	t.Setenv("APM_SESSION_ID", uniqueSessionID("sleep"))
	_ = KillSession()
	defer KillSession()

	if err := CreateLockingSession("pass", time.Hour, false, 0, true); err != nil {
		t.Fatalf("CreateLockingSession failed: %v", err)
	}
	if _, err := GetSession(); err != nil {
		t.Fatalf("session ended without sleeping: %v", err)
	}

	// Pretend the session started before a sleep the computer has since woken from.
	mark, _ := sleepMark()
	sess := Session{MasterPassword: "pass", LastUsed: time.Now(), Expiry: time.Now().Add(time.Hour), LockOnSleep: true, SleepMark: mark - 100}
	data, err := encryptSessionData(sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(getSessionFile(), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PeekSession(); err == nil {
		t.Fatal("PeekSession accepted a session from before a sleep")
	}
	if _, err := GetSession(); err == nil || err.Error() != "session locked because the computer slept" {
		t.Fatalf("expected the sleep lock, got %v", err)
	}
}
