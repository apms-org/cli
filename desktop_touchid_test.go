package main

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestTouchIDPromptRoundTrip checks that under the desktop app pm hands the
// fingerprint check to the app and maps its answer, instead of running
// osascript.
func TestTouchIDPromptRoundTrip(t *testing.T) {
	t.Setenv("APM_DESKTOP_TOUCHID", "app")
	cases := []struct {
		reply map[string]any
		code  string
	}{
		{map[string]any{"ok": true}, ""},
		{map[string]any{"ok": false, "code": "cancelled"}, "touchid_cancelled"},
		{map[string]any{"ok": false, "code": "failed"}, "touchid_failed"},
		{map[string]any{"ok": false, "code": "lockout"}, "touchid_locked"},
		{map[string]any{"ok": false, "code": "unavailable"}, "touchid_unavailable"},
	}
	for _, c := range cases {
		s := &desktopServer{touchWait: map[int64]chan touchReply{}}
		prompts := make(chan map[string]any, 1)
		s.sink = func(event string, data any) {
			if event == "touchid.prompt" {
				prompts <- data.(map[string]any)
			}
		}
		done := make(chan error, 1)
		go func() { done <- s.verifyTouchID("unlock your vault", true) }()

		var prompt map[string]any
		select {
		case prompt = <-prompts:
		case <-time.After(2 * time.Second):
			t.Fatal("no touchid.prompt event")
		}
		if prompt["inline"] != true || prompt["reason"] != "unlock your vault" {
			t.Fatalf("prompt = %v", prompt)
		}
		params := map[string]any{"id": prompt["id"]}
		for k, v := range c.reply {
			params[k] = v
		}
		raw, _ := json.Marshal(params)
		if _, err := hTouchIDReply(s, raw); err != nil {
			t.Fatalf("reply: %v", err)
		}

		var err error
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("verifyTouchID did not return after the reply")
		}
		if c.code == "" {
			if err != nil {
				t.Errorf("reply %v: got %v, want nil", c.reply, err)
			}
			continue
		}
		var re *rpcError
		if !errors.As(err, &re) || re.Code != c.code {
			t.Errorf("reply %v: got %v, want %s", c.reply, err, c.code)
		}
		if len(s.touchWait) != 0 {
			t.Errorf("reply %v: %d prompts still pending", c.reply, len(s.touchWait))
		}
	}
}

// A reply for a prompt that is not pending is ignored.
func TestTouchIDReplyUnknown(t *testing.T) {
	s := &desktopServer{touchWait: map[int64]chan touchReply{}}
	if _, err := hTouchIDReply(s, json.RawMessage(`{"id":42,"ok":true}`)); err != nil {
		t.Fatalf("reply: %v", err)
	}
}
