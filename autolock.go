package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// autoLocker applies the vault's auto-lock policy to a bridge that runs
// without the desktop app: pm bridge serve and the native messaging host. The
// app applies the same policy in its own window.
type autoLocker struct {
	s *desktopServer
	// idle, when set, overrides the policy's inactivity limit (pm bridge serve
	// --idle). Zero turns idle locking off.
	idle       *time.Duration
	mu         sync.Mutex
	unlockedAt time.Time
	active     time.Time
	onLock     func(reason string)
}

// sleepGap is how far the wall clock must run ahead of the monotonic clock
// between two ticks before it counts as the computer having slept. The
// monotonic clock stops during sleep on macOS, Linux and Windows.
const sleepGap = 20 * time.Second

func newAutoLocker(s *desktopServer) *autoLocker {
	return &autoLocker{s: s}
}

func (a *autoLocker) markUnlocked() {
	now := time.Now()
	a.mu.Lock()
	a.unlockedAt = now
	a.active = now
	a.mu.Unlock()
}

func (a *autoLocker) touch() {
	a.mu.Lock()
	a.active = time.Now()
	a.mu.Unlock()
}

func (a *autoLocker) times() (time.Time, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	active := a.active
	if seen := a.s.bridge.lastActiveAt(); seen.After(active) {
		active = seen
	}
	return a.unlockedAt, active
}

// reason returns why the vault should lock now, or "".
func (a *autoLocker) reason(now time.Time, slept bool) string {
	if !a.s.unlocked() {
		return ""
	}
	p := lockPolicyOf(a.s.vault)
	if a.idle != nil {
		p.Idle = *a.idle
	}
	unlockedAt, active := a.times()
	switch {
	case slept && p.Sleep:
		return "sleep"
	case p.Idle > 0 && !active.IsZero() && now.Sub(active) >= p.Idle:
		return "idle"
	case p.Max > 0 && !unlockedAt.IsZero() && now.Sub(unlockedAt) >= p.Max:
		return "expired"
	}
	return ""
}

func lockReasonText(reason string, p lockPolicy) string {
	switch reason {
	case "sleep":
		return "Locked when the computer went to sleep"
	case "idle":
		return fmt.Sprintf("Locked after %s idle", lockDurationText(p.Idle))
	case "expired":
		return fmt.Sprintf("Locked after %s, the maximum session", lockDurationText(p.Max))
	}
	return "Locked"
}

func (a *autoLocker) run(stop <-chan struct{}) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	prev := time.Now()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			now = time.Now()
			slept := now.Round(0).Sub(prev.Round(0))-now.Sub(prev) > sleepGap
			prev = now
			a.check(now, slept)
		}
	}
}

func (a *autoLocker) check(now time.Time, slept bool) {
	s := a.s
	s.mu.Lock()
	why := a.reason(now, slept)
	if why == "" {
		s.mu.Unlock()
		return
	}
	p := lockPolicyOf(s.vault)
	if a.idle != nil {
		p.Idle = *a.idle
	}
	text := lockReasonText(why, p)
	params, _ := json.Marshal(map[string]any{"reason": text})
	_, err := hVaultLock(s, params)
	if err == nil {
		s.emit("vault.locked", map[string]any{"reason": text, "why": why})
	}
	s.mu.Unlock()
	if err == nil && a.onLock != nil {
		a.onLock(text)
	}
}
