package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func maskBridgeToken(t string) string {
	if len(t) <= 10 {
		return t
	}
	return t[:6] + "..." + t[len(t)-4:]
}

func bridgeTokenFingerprint(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6]
}

func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage of each socket address")
}

func (s *desktopServer) adoptUnlock(password string, v *src.Vault, readonly bool) {
	s.vault = v
	s.password = password
	s.rec = nil
	if data, err := os.ReadFile(s.vaultPath); err == nil {
		s.lastWriteHash = sha256Hex(data)
	}
	if readonly {
		until := time.Now().Add(time.Hour)
		if sess, err := src.PeekSession(); err == nil && sess != nil && !sess.Expiry.IsZero() {
			until = sess.Expiry
		}
		s.readonlyUntil = until
	}
	s.markKnownTx()
	src.LogAction("VAULT_UNLOCKED", "Browser bridge unlocked from the terminal")
}

type serveUI struct {
	s           *desktopServer
	locker      *autoLocker
	interactive bool
	out         sync.Mutex
	lines       chan string
	pairs       chan map[string]any
	done        chan map[string]any
}

func newServeUI(s *desktopServer, interactive bool) *serveUI {
	return &serveUI{s: s, interactive: interactive, lines: make(chan string, 16), pairs: make(chan map[string]any, 8), done: make(chan map[string]any, 32)}
}

func (u *serveUI) printf(format string, args ...any) {
	u.out.Lock()
	defer u.out.Unlock()
	fmt.Printf("%s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func (u *serveUI) event(name string, data any) {
	d, _ := data.(map[string]any)
	switch name {
	case "vault.unlocked":
		if u.locker != nil {
			u.locker.markUnlocked()
		}
		via := "the browser"
		if toStr(d["via"]) == "browser-touchid" {
			via = "the browser with Touch ID"
		}
		u.printf("Vault unlocked from %s.", via)
	case "vault.locked":
		reason := toStr(d["reason"])
		if reason == "" {
			reason = "Locked"
		}
		u.printf("Vault locked: %s.", strings.TrimSuffix(reason, "."))
	case "bridge.pair":
		select {
		case u.pairs <- d:
		default:
		}
	case "bridge.pairDone":
		select {
		case u.done <- d:
		default:
		}
	}
}

func (u *serveUI) readStdin() {
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if line != "" || err == nil {
			u.lines <- strings.TrimSpace(line)
		}
		if err != nil {
			close(u.lines)
			return
		}
	}
}

func (u *serveUI) answer(id, client string, allow bool) {
	params, _ := json.Marshal(map[string]any{"id": id, "allow": allow})
	u.s.mu.Lock()
	res, err := hBridgePairRespond(u.s, params)
	u.s.mu.Unlock()
	if err != nil {
		u.printf("Could not answer the request from %s: %v", client, err)
		return
	}
	status := ""
	if m, ok := res.(map[string]any); ok {
		status = toStr(m["status"])
	}
	if status == "approved" {
		u.printf("Connected %s.", client)
	} else {
		u.printf("Did not connect %s.", client)
	}
}

func (u *serveUI) waitAnswer(id string) (bool, bool) {
	for {
		select {
		case line, ok := <-u.lines:
			if !ok {
				u.interactive = false
				fmt.Println()
				u.printf("Input closed, so the request was denied.")
				return false, true
			}
			a := strings.ToLower(line)
			return a == "y" || a == "yes", true
		case d := <-u.done:
			if toStr(d["id"]) != id {
				continue
			}
			fmt.Println()
			u.printf("The pairing request was %s.", toStr(d["status"]))
			return false, false
		}
	}
}

func (u *serveUI) run() {
	if u.interactive {
		go u.readStdin()
	}
	for req := range u.pairs {
		id := toStr(req["id"])
		client := toStr(req["client"])
		code := formatPairCode(toStr(req["code"]))
		if !u.interactive {
			u.printf("%s asked to connect (code %s). Denied because this terminal cannot answer. Run 'pm extension serve' in a terminal, or paste the token from 'pm extension token --show' into the extension.", client, code)
			u.answer(id, client, false)
			continue
		}
		for drained := false; !drained; {
			select {
			case <-u.lines:
			default:
				drained = true
			}
		}
		u.out.Lock()
		fmt.Printf("Connect %s? Code %s [y/N] ", client, code)
		u.out.Unlock()
		allow, answered := u.waitAnswer(id)
		if answered {
			u.answer(id, client, allow)
		}
	}
}

func newExtensionServeCmd() *cobra.Command {
	var port int
	var locked, promptStdin bool
	var idle time.Duration
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the extension from this terminal instead of linking pm",
		Long:  "Serve the loopback bridge the APM browser extension talks to, on 127.0.0.1, until you press Ctrl+C. It serves the same HTTP API as the desktop app and asks you here to approve pairing requests.\n\nMost people should run 'pm extension link' once instead, so the browser starts pm on its own. Use serve to watch requests live, to pick the idle timeout, or to avoid registering pm with your browsers.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			var override *time.Duration
			if cmd.Flags().Changed("idle") {
				override = &idle
			}
			os.Exit(runBridgeServe(port, locked, override, promptStdin))
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "Port to listen on (default 41417, or APM_BRIDGE_PORT)")
	cmd.Flags().BoolVar(&locked, "locked", false, "Start locked and let the extension unlock the vault")
	cmd.Flags().DurationVar(&idle, "idle", 0, "Lock after this long without browser activity, 0 for never (default: the vault's auto-lock, see pm autolock)")
	cmd.Flags().BoolVar(&promptStdin, "prompt-stdin", false, "Read pairing answers from stdin even when it is not a terminal")
	_ = cmd.Flags().MarkHidden("prompt-stdin")
	return cmd
}

func runBridgeServe(port int, locked bool, idle *time.Duration, promptStdin bool) int {
	s := newDesktopServer(nil)
	s.bridge.mode = "serve"
	if port > 0 {
		s.bridge.port = port
	}
	if !src.VaultExists(s.vaultPath) {
		color.Red("No vault found at %s. Run 'pm setup' first.", s.vaultPath)
		return 1
	}
	ui := newServeUI(s, promptStdin || term.IsTerminal(int(os.Stdin.Fd())))
	locker := newAutoLocker(s)
	locker.idle = idle
	ui.locker = locker
	s.sink = ui.event
	if err := s.bridge.start(); err != nil {
		if isAddrInUse(err) {
			color.Red("Port %d is in use. The APM app may already be serving the extension.", s.bridge.port)
		} else {
			color.Red("Could not start the bridge on 127.0.0.1:%d: %v", s.bridge.port, err)
		}
		return 1
	}
	if !locked {
		s.mu.Lock()
		_, err := hVaultUnlockSession(s, nil)
		s.mu.Unlock()
		if err != nil {
			var re *rpcError
			if !errors.As(err, &re) || re.Code != "locked" {
				color.Red("%v", err)
				s.shutdown()
				return 1
			}
			pass, v, readonly, uerr := src_unlockVault()
			if uerr != nil {
				color.Red("%v", uerr)
				s.shutdown()
				return 1
			}
			s.mu.Lock()
			s.adoptUnlock(pass, v, readonly)
			s.mu.Unlock()
		}
		locker.markUnlocked()
	}
	s.startWatcher()
	s.mu.Lock()
	state := "locked"
	policy := defaultLockPolicy()
	if s.unlocked() {
		state = "unlocked"
		policy = lockPolicyOf(s.vault)
	}
	s.mu.Unlock()
	if idle != nil {
		policy.Idle = *idle
	}
	fmt.Printf("Browser extension bridge on 127.0.0.1:%d · %s · %s\n", s.bridge.port, s.vaultPath, state)
	if state == "unlocked" && policy.never() && !policy.Sleep {
		fmt.Println("Never locks on its own. Press Ctrl+C to stop.")
	} else if state == "unlocked" {
		fmt.Printf("Locks %s. Press Ctrl+C to stop.\n", policy.summary())
	} else {
		fmt.Println("Press Ctrl+C to stop.")
	}
	go ui.run()
	stop := make(chan struct{})
	go locker.run(stop)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	close(stop)
	s.shutdown()
	fmt.Println()
	fmt.Println("Bridge stopped. The vault key was dropped from memory.")
	return 0
}

func newExtensionTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Print the browser extension pairing token",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			show, _ := cmd.Flags().GetBool("show")
			token, err := ensureBridgeToken()
			if err != nil {
				cliFail("Could not read or create the pairing token: %v", err)
			}
			if show {
				fmt.Println(token)
				return
			}
			fmt.Printf("Pairing token: %s\n", maskBridgeToken(token))
			fmt.Println("Run 'pm extension token --show' to print it in full, then paste it into the extension's manual pairing field.")
		},
	}
	cmd.Flags().Bool("show", false, "Print the full token")
	return cmd
}

func newExtensionRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Replace the pairing token so every paired browser must pair again",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if _, _, _, err := src_unlockVault(); err != nil {
				cliFail("%v", err)
			}
			token := newBridgeToken()
			if err := writeBridgeToken(token); err != nil {
				cliFail("Could not write the pairing token: %v", err)
			}
			src.LogAction("BRIDGE_TOKEN_ROTATED", "Browser extension pairing token rotated from the CLI")
			color.Green("New pairing token: %s", maskBridgeToken(token))
			fmt.Println("Paired browsers must pair again. A running bridge picks up the new token on its next request.")
		},
	}
}
