package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	src "github.com/aaravmaloo/apm/src"
)

func TestParseLockDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		bad  bool
	}{
		{"never", 0, false},
		{"Off", 0, false},
		{"0", 0, false},
		{"15", 15 * time.Minute, false},
		{"15m", 15 * time.Minute, false},
		{"4h", 4 * time.Hour, false},
		{"90s", 2 * time.Minute, false},
		{"1m30s", 2 * time.Minute, false},
		{"0s", 0, false},
		{"", 0, true},
		{"banana", 0, true},
		{"-5m", 0, true},
		{"800h", 0, true},
	}
	for _, c := range cases {
		got, err := parseLockDuration(c.in)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("parseLockDuration(%q) = %v, %v; want %v, bad=%v", c.in, got, err, c.want, c.bad)
		}
	}
}

func TestLockPolicyRoundTrip(t *testing.T) {
	v := &src.Vault{}
	if got := lockPolicyOf(v); got != (lockPolicy{Idle: 15 * time.Minute, Max: time.Hour, Sleep: true}) {
		t.Fatalf("default policy = %+v", got)
	}
	want := lockPolicy{Idle: 0, Max: 8 * time.Hour, Sleep: false}
	want.apply(v)
	if v.Desktop.Settings["inactivity"] != "0" || v.Desktop.Settings["sessionTimeout"] != "480" {
		t.Fatalf("stored settings = %v", v.Desktop.Settings)
	}
	if got := lockPolicyOf(v); got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	// The app stores strings; older vaults or other writers may hold numbers.
	v.Desktop.Settings = map[string]any{"inactivity": float64(5), "sessionTimeout": "junk", "lockOnSleep": "false"}
	if got := lockPolicyOf(v); got != (lockPolicy{Idle: 5 * time.Minute, Max: time.Hour, Sleep: false}) {
		t.Fatalf("mixed settings = %+v", got)
	}
}

func TestLockPolicySummary(t *testing.T) {
	cases := []struct {
		p    lockPolicy
		want string
	}{
		{lockPolicy{Idle: 15 * time.Minute, Max: time.Hour, Sleep: true}, "after 15 minutes idle, 1 hour at most and on sleep"},
		{lockPolicy{Idle: time.Minute, Max: 0, Sleep: false}, "after 1 minute idle"},
		{lockPolicy{Idle: 0, Max: 24 * time.Hour, Sleep: true}, "24 hours at most and on sleep"},
		{lockPolicy{Idle: 48 * time.Hour}, "after 2 days idle"},
		{lockPolicy{}, "never on its own"},
	}
	for _, c := range cases {
		if got := c.p.summary(); got != c.want {
			t.Errorf("summary(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

func lockerFor(p lockPolicy) (*autoLocker, *desktopServer) {
	v := &src.Vault{}
	p.apply(v)
	s := &desktopServer{vault: v, password: "pw"}
	s.bridge = newDesktopBridge(s)
	return newAutoLocker(s), s
}

func TestAutoLockerReasons(t *testing.T) {
	now := time.Now()
	a, s := lockerFor(lockPolicy{Idle: 15 * time.Minute, Max: time.Hour, Sleep: true})
	a.unlockedAt, a.active = now.Add(-10*time.Minute), now.Add(-5*time.Minute)
	if got := a.reason(now, false); got != "" {
		t.Fatalf("fresh session locked: %q", got)
	}
	if got := a.reason(now, true); got != "sleep" {
		t.Fatalf("sleep: %q", got)
	}
	a.active = now.Add(-16 * time.Minute)
	if got := a.reason(now, false); got != "idle" {
		t.Fatalf("idle: %q", got)
	}
	// A passive request (a status poll) does not count as activity, an
	// active one does.
	s.bridge.touch("Chrome", "chrome-extension://x", false)
	if got := a.reason(now, false); got != "idle" {
		t.Fatalf("status poll kept it unlocked: %q", got)
	}
	s.bridge.touch("Chrome", "chrome-extension://x", true)
	if got := a.reason(time.Now(), false); got != "" {
		t.Fatalf("fill did not count as activity: %q", got)
	}
	a.unlockedAt = now.Add(-61 * time.Minute)
	if got := a.reason(time.Now(), false); got != "expired" {
		t.Fatalf("max session: %q", got)
	}

	never, _ := lockerFor(lockPolicy{})
	never.unlockedAt, never.active = now.Add(-72*time.Hour), now.Add(-72*time.Hour)
	if got := never.reason(now, true); got != "" {
		t.Fatalf("never policy locked: %q", got)
	}

	override := 0 * time.Minute
	a2, _ := lockerFor(lockPolicy{Idle: time.Minute, Max: 0, Sleep: false})
	a2.idle = &override
	a2.unlockedAt, a2.active = now.Add(-time.Hour), now.Add(-time.Hour)
	if got := a2.reason(now, false); got != "" {
		t.Fatalf("--idle 0 override ignored: %q", got)
	}
}

func TestNativeHostOrigin(t *testing.T) {
	if o, ok := nativeHostOrigin([]string{"chrome-extension://ioooalainhfihaebgpbmngoaojmfdlac/", "--parent-window=0"}); !ok || o != "chrome-extension://ioooalainhfihaebgpbmngoaojmfdlac/" {
		t.Fatalf("windows-style args: %q %v", o, ok)
	}
	for _, args := range [][]string{nil, {"get"}, {"chrome-extension://"}, {"desktop"}} {
		if _, ok := nativeHostOrigin(args); ok {
			t.Fatalf("%v treated as a native host launch", args)
		}
	}
}

func TestNativeReplyChunks(t *testing.T) {
	var out bytes.Buffer
	h := &nativeHost{out: &out}
	value := strings.Repeat("é", nativeChunk) // two bytes each, so cuts land mid-rune unless handled
	body, _ := json.Marshal(map[string]any{"ok": true, "value": value})
	h.reply(json.Number("7"), 200, body)

	r := bufio.NewReader(&out)
	var joined strings.Builder
	parts := 0
	for {
		var n uint32
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			break
		}
		if n > 1<<20 {
			t.Fatalf("message of %d bytes is over the browser's 1 MiB limit", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			t.Fatal(err)
		}
		var m struct {
			Part  int    `json:"part"`
			Parts int    `json:"parts"`
			Chunk string `json:"chunk"`
		}
		if err := json.Unmarshal(buf, &m); err != nil {
			t.Fatal(err)
		}
		if m.Part != parts {
			t.Fatalf("part %d arrived as %d", parts, m.Part)
		}
		joined.WriteString(m.Chunk)
		parts++
	}
	if parts < 3 {
		t.Fatalf("want at least 3 parts, got %d", parts)
	}
	var whole struct {
		ID     json.Number `json:"id"`
		Status int         `json:"status"`
		Body   struct {
			Value string `json:"value"`
		} `json:"body"`
	}
	if err := json.Unmarshal([]byte(joined.String()), &whole); err != nil {
		t.Fatalf("parts do not join into JSON: %v", err)
	}
	if whole.ID != "7" || whole.Status != 200 || whole.Body.Value != value {
		t.Fatalf("joined answer differs: id=%s status=%d len=%d", whole.ID, whole.Status, len(whole.Body.Value))
	}
}
