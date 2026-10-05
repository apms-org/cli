package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type nativeBrowser struct {
	id   string
	name string
	// mac and linux are the browser's folder under ~/Library/Application
	// Support and ~/.config. win is its folder under %LOCALAPPDATA% and reg
	// its key under HKCU.
	mac   string
	linux string
	win   string
	reg   string
}

var nativeBrowsers = []nativeBrowser{
	{id: "chrome", name: "Google Chrome", mac: "Google/Chrome", linux: "google-chrome", win: `Google\Chrome\User Data`, reg: `Software\Google\Chrome`},
	{id: "chrome-beta", name: "Chrome Beta", mac: "Google/Chrome Beta", linux: "google-chrome-beta"},
	{id: "chrome-canary", name: "Chrome Canary", mac: "Google/Chrome Canary", linux: "google-chrome-unstable"},
	{id: "chromium", name: "Chromium", mac: "Chromium", linux: "chromium", win: `Chromium\User Data`, reg: `Software\Chromium`},
	{id: "edge", name: "Microsoft Edge", mac: "Microsoft Edge", linux: "microsoft-edge", win: `Microsoft\Edge\User Data`, reg: `Software\Microsoft\Edge`},
	{id: "brave", name: "Brave", mac: "BraveSoftware/Brave-Browser", linux: "BraveSoftware/Brave-Browser", win: `BraveSoftware\Brave-Browser\User Data`, reg: `Software\BraveSoftware\Brave-Browser`},
	{id: "vivaldi", name: "Vivaldi", mac: "Vivaldi", linux: "vivaldi", win: `Vivaldi\User Data`, reg: `Software\Vivaldi`},
	{id: "arc", name: "Arc", mac: "Arc/User Data"},
}

var extensionIDPattern = regexp.MustCompile(`^[a-p]{32}$`)

// browserDir is the browser's profile folder on this system, or "" when the
// browser has no such folder here.
func (b nativeBrowser) browserDir() string {
	switch runtime.GOOS {
	case "darwin":
		if b.mac == "" {
			return ""
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, "Library", "Application Support", filepath.FromSlash(b.mac))
	case "windows":
		if b.win == "" {
			return ""
		}
		return filepath.Join(os.Getenv("LOCALAPPDATA"), b.win)
	default:
		if b.linux == "" {
			return ""
		}
		dir, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		return filepath.Join(dir, filepath.FromSlash(b.linux))
	}
}

func (b nativeBrowser) installed() bool {
	dir := b.browserDir()
	if dir == "" {
		return false
	}
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

// manifestFile is where the browser reads the host manifest. On Windows the
// manifest lives in the APM config folder and a registry key points to it.
func (b nativeBrowser) manifestFile() string {
	if runtime.GOOS == "windows" {
		if b.reg == "" {
			return ""
		}
		if d := apmConfigDir(); d != "" {
			return filepath.Join(d, "native-messaging", nativeHostName+".json")
		}
		return ""
	}
	dir := b.browserDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "NativeMessagingHosts", nativeHostName+".json")
}

func (b nativeBrowser) regKey() string {
	return `HKCU\` + b.reg + `\NativeMessagingHosts\` + nativeHostName
}

func findNativeBrowser(id string) (nativeBrowser, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, b := range nativeBrowsers {
		if b.id == id {
			return b, true
		}
	}
	return nativeBrowser{}, false
}

func nativeBrowserIDs() string {
	var ids []string
	for _, b := range nativeBrowsers {
		if b.manifestFileFor(runtime.GOOS) {
			ids = append(ids, b.id)
		}
	}
	return strings.Join(ids, ", ")
}

func (b nativeBrowser) manifestFileFor(goos string) bool {
	switch goos {
	case "darwin":
		return b.mac != ""
	case "windows":
		return b.reg != ""
	default:
		return b.linux != ""
	}
}

// nativeHostBinary is the pm the browser should start. It prefers the pm on
// PATH when that is this same file, because a package manager's symlink
// survives upgrades and the versioned path behind it does not.
func nativeHostBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	if p, err := exec.LookPath("pm"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			a, aerr := os.Stat(abs)
			b, berr := os.Stat(exe)
			if aerr == nil && berr == nil && os.SameFile(a, b) {
				return abs, nil
			}
		}
	}
	return exe, nil
}

func nativeManifest(binary string, ids []string) map[string]any {
	origins := []string{}
	for _, id := range ids {
		origins = append(origins, "chrome-extension://"+id+"/")
	}
	return map[string]any{
		"name":            nativeHostName,
		"description":     "APM password manager (pm). Lets the APM extension fill from your vault when the APM app is closed.",
		"path":            binary,
		"type":            "stdio",
		"allowed_origins": origins,
	}
}

func installNativeManifest(b nativeBrowser, manifest map[string]any) (string, error) {
	file := b.manifestFile()
	if file == "" {
		return "", fmt.Errorf("%s is not supported on this system", b.name)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(file, append(data, '\n'), 0644); err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("reg", "add", b.regKey(), "/ve", "/t", "REG_SZ", "/d", file, "/f").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("could not register with %s: %s", b.name, strings.TrimSpace(string(out)))
		}
	}
	return file, nil
}

func removeNativeManifest(b nativeBrowser) bool {
	if runtime.GOOS == "windows" {
		if b.reg == "" {
			return false
		}
		return exec.Command("reg", "delete", b.regKey(), "/f").Run() == nil
	}
	file := b.manifestFile()
	if file == "" {
		return false
	}
	return os.Remove(file) == nil
}

// linkedManifest reads the manifest pm extension link left for a browser.
func linkedManifest(b nativeBrowser) (map[string]any, bool) {
	if runtime.GOOS == "windows" {
		if b.reg == "" || exec.Command("reg", "query", b.regKey()).Run() != nil {
			return nil, false
		}
	}
	file := b.manifestFile()
	if file == "" {
		return nil, false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil, false
	}
	return m, true
}

// appBridgeRunning reports whether the desktop app or pm extension serve is
// already answering on the loopback port.
func appBridgeRunning() (string, bool) {
	client := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/info", bridgePortFromEnv()))
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var info struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if json.NewDecoder(resp.Body).Decode(&info) != nil || info.Name != "APM" {
		return "", false
	}
	return info.Mode, true
}

func newExtensionCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "extension",
		Short: "Connect the APM browser extension to your vault without the desktop app",
		Long: "The APM browser extension fills from your vault through the desktop app. Link it once with 'pm extension link' and the browser starts pm on its own whenever the app is closed. A linked pm only ever answers the APM extension, and only after you confirm the code it shows.\n\n" +
			"'pm extension serve' serves the extension from a terminal instead. 'pm extension token' and 'pm extension rotate' manage the pairing token the app, serve and a linked pm share.",
	}
	root.AddCommand(newExtensionLinkCmd(), newExtensionUnlinkCmd(), newExtensionStatusCmd(), newExtensionServeCmd(), newExtensionTokenCmd(), newExtensionRotateCmd(), newExtensionHostCmd())
	return root
}

func newExtensionLinkCmd() *cobra.Command {
	var browsers []string
	var ids []string
	var noWait bool
	cmd := &cobra.Command{
		Use:   "link",
		Short: "Let the browser extension use pm when the desktop app is closed",
		Long: "Registers pm with each Chromium browser on this computer (Chrome, Edge, Brave, Arc, Vivaldi, Chromium) so the APM extension can start it, then waits for the extension to connect.\n\n" +
			"If the extension is not paired yet, it shows a code. Check that the same code appears here and answer y. You only do this once per browser.",
		Example: "  pm extension link\n  pm extension link --browser chrome\n  pm extension link --no-wait",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runExtensionLink(browsers, ids, noWait))
		},
	}
	cmd.Flags().StringSliceVar(&browsers, "browser", nil, "Only link these browsers ("+nativeBrowserIDs()+")")
	cmd.Flags().StringSliceVar(&ids, "id", nil, "Also allow this extension ID, for a development build")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Register and exit without waiting for the browser")
	return cmd
}

func runExtensionLink(only, extraIDs []string, noWait bool) int {
	if !src.VaultExists(vaultPath) {
		color.Red("No vault found at %s. Run 'pm setup' first.", vaultPath)
		return 1
	}
	ids := []string{apmExtensionID}
	for _, id := range extraIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if !extensionIDPattern.MatchString(id) {
			color.Red("%q is not an extension ID. It is 32 letters from a to p, shown in chrome://extensions.", id)
			return 1
		}
		if id != apmExtensionID {
			ids = append(ids, id)
		}
	}
	targets, err := linkTargets(only)
	if err != nil {
		color.Red("%v", err)
		return 1
	}
	binary, err := nativeHostBinary()
	if err != nil {
		color.Red("Could not find the pm executable: %v", err)
		return 1
	}
	if strings.Contains(binary, "go-build") || strings.HasPrefix(binary, filepath.Clean(os.TempDir())+string(filepath.Separator)) {
		color.Yellow("pm is running from a temporary build at %s. Build it with 'go build' and link from the built binary, or the browser loses it.", binary)
	}

	manifest := nativeManifest(binary, ids)
	var linked []string
	var names []string
	for _, b := range targets {
		file, err := installNativeManifest(b, manifest)
		if err != nil {
			color.Red("%s: %v", b.name, err)
			continue
		}
		linked = append(linked, b.id)
		names = append(names, b.name)
		fmt.Printf("  %-15s %s\n", b.name, file)
	}
	if len(linked) == 0 {
		color.Red("No browser was linked.")
		return 1
	}
	if err := writeJSONFile(nativeHostConfigFile(), nativeHostConfig{Vault: vaultPath, Path: binary, Linked: ms(time.Now()), Browsers: linked, IDs: ids}); err != nil {
		color.Red("Could not save the link settings: %v", err)
		return 1
	}
	if _, err := ensureBridgeToken(); err != nil {
		color.Red("Could not create the pairing token: %v", err)
		return 1
	}
	src.LogAction("EXTENSION_LINKED", strings.Join(linked, ", "))
	color.Green("Linked %s.", joinNames(names))
	fmt.Printf("The browser starts %s when the APM app is closed, for the vault at %s.\n", binary, vaultPath)

	if mode, ok := appBridgeRunning(); ok {
		if mode == "serve" {
			fmt.Println("\n'pm extension serve' is running, so the extension uses it for now. Stop it and the browser starts pm on its own.")
		} else {
			fmt.Println("\nThe APM app is running, so the extension uses it for now. Close the app and the browser starts pm on its own.")
		}
		fmt.Println("If the extension is not paired yet, approve it in the app.")
		return 0
	}
	if noWait || !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("\nNext, click the APM icon in your browser. If it asks to connect, run 'pm extension link' again in a terminal to confirm the code.")
		return 0
	}
	return waitForExtension()
}

func linkTargets(only []string) ([]nativeBrowser, error) {
	if len(only) > 0 {
		var out []nativeBrowser
		for _, id := range only {
			b, ok := findNativeBrowser(id)
			if !ok || !b.manifestFileFor(runtime.GOOS) {
				return nil, fmt.Errorf("%q is not a browser pm can link here. Use one of: %s", id, nativeBrowserIDs())
			}
			out = append(out, b)
		}
		return out, nil
	}
	var out []nativeBrowser
	for _, b := range nativeBrowsers {
		if b.manifestFileFor(runtime.GOOS) && b.installed() {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("No Chromium browser found. Pass --browser to link one anyway, for example --browser chrome.")
	}
	return out, nil
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}

const linkWait = 5 * time.Minute

// waitForExtension answers the extension's first connection from the
// terminal: it shows the pairing request the native host left and records the
// answer, or notices that an already paired extension has connected.
func waitForExtension() int {
	start := time.Now()
	fmt.Println()
	fmt.Println("Now click the APM icon in your browser.")
	fmt.Println("If it shows a code, check it matches the one here. Waiting for the browser (Ctrl+C to finish now)...")

	lines := make(chan string)
	go func() {
		r := bufio.NewReader(os.Stdin)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				close(lines)
				return
			}
			lines <- strings.TrimSpace(line)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	answered := map[string]bool{}
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(linkWait)
	for {
		select {
		case <-sig:
			fmt.Println()
			fmt.Println("Stopped waiting. pm stays linked, so the extension can still connect later. Run 'pm extension link' again to confirm a code.")
			return 0
		case <-deadline:
			fmt.Println("Nothing connected within 5 minutes. pm stays linked. Run 'pm extension link' again when you are at the browser.")
			return 0
		case <-tick.C:
		}
		if seenSince(start) {
			color.Green("The extension is connected. It now works without the APM app.")
			return 0
		}
		req, err := readLinkRequest()
		if err != nil || req.Status != "pending" || answered[req.ID] || time.Now().UnixMilli() > req.Expires {
			continue
		}
		answered[req.ID] = true
		client := req.Client
		if client == "" {
			client = "A browser"
		}
		fmt.Printf("\n%s asks to connect. Code %s. Connect it? [y/N] ", client, formatPairCode(req.Code))
		var line string
		var ok bool
		select {
		case line, ok = <-lines:
		case <-sig:
			fmt.Println()
			denyLinkRequest(req.ID)
			fmt.Println("Cancelled. The request was denied.")
			return 1
		}
		if !ok {
			fmt.Println()
			denyLinkRequest(req.ID)
			fmt.Println("Input closed, so the request was denied.")
			return 1
		}
		if a := strings.ToLower(line); a != "y" && a != "yes" {
			denyLinkRequest(req.ID)
			src.LogAction("BRIDGE_PAIR_DENIED", client+" (pm extension link)")
			fmt.Printf("Did not connect %s.\n", client)
			continue
		}
		cur, err := readLinkRequest()
		if err != nil || cur.ID != req.ID || cur.Status != "pending" || time.Now().UnixMilli() > cur.Expires {
			color.Yellow("That request expired. Click the APM icon in the browser to get a new code.")
			continue
		}
		cur.Status = "approved"
		if err := writeLinkRequest(cur); err != nil {
			color.Red("Could not record the answer: %v", err)
			return 1
		}
		src.LogAction("BRIDGE_PAIRED", client+" (pm extension link)")
		if waitLinkTaken(cur.ID, 15*time.Second) {
			color.Green("Connected %s. The extension now works without the APM app.", client)
		} else {
			color.Green("Approved %s. The browser finishes connecting the next time it checks.", client)
		}
		return 0
	}
}

func seenSince(t time.Time) bool {
	file := extensionSeenFile()
	if file == "" {
		return false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	var seen struct {
		TS int64 `json:"ts"`
	}
	return json.Unmarshal(data, &seen) == nil && seen.TS >= t.UnixMilli()
}

func denyLinkRequest(id string) {
	if cur, err := readLinkRequest(); err == nil && cur.ID == id && cur.Status == "pending" {
		cur.Status = "denied"
		_ = writeLinkRequest(cur)
	}
}

func waitLinkTaken(id string, limit time.Duration) bool {
	until := time.Now().Add(limit)
	for time.Now().Before(until) {
		cur, err := readLinkRequest()
		if errors.Is(err, os.ErrNotExist) || (err == nil && cur.ID != id) {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func newExtensionUnlinkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlink",
		Short: "Stop browsers from starting pm for the extension",
		Long:  "Removes pm from every browser 'pm extension link' registered it with. The extension keeps working while the APM app is open.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			var names []string
			for _, b := range nativeBrowsers {
				if !b.manifestFileFor(runtime.GOOS) {
					continue
				}
				if _, ok := linkedManifest(b); !ok {
					continue
				}
				if removeNativeManifest(b) {
					names = append(names, b.name)
				}
			}
			for _, f := range []string{nativeHostConfigFile(), extensionLinkFile(), extensionSeenFile()} {
				if f != "" {
					_ = os.Remove(f)
				}
			}
			if runtime.GOOS == "windows" {
				if d := apmConfigDir(); d != "" {
					_ = os.Remove(filepath.Join(d, "native-messaging", nativeHostName+".json"))
				}
			}
			if len(names) == 0 {
				fmt.Println("pm was not linked with any browser.")
				return
			}
			src.LogAction("EXTENSION_UNLINKED", strings.Join(names, ", "))
			color.Green("Unlinked %s.", joinNames(names))
			fmt.Println("The extension works only while the APM app is open. Its pairing is kept; run 'pm extension rotate' to revoke it.")
		},
	}
}

func newExtensionStatusCmd() *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show linked browsers, the running bridge and the pairing token",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runExtensionStatus(port))
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "Port to probe (default 41417, or APM_BRIDGE_PORT)")
	return cmd
}

func statusLine(label, value string) {
	fmt.Printf("%-16s %s\n", label+":", value)
}

// runExtensionStatus exits 1 when the extension has no way to reach pm (no
// bridge listening and no browser linked) or the running bridge rejects the
// local pairing token.
func runExtensionStatus(port int) int {
	if port <= 0 {
		port = bridgePortFromEnv()
	}
	binary, _ := nativeHostBinary()
	type row struct{ name, state string }
	var rows []row
	linked := 0
	for _, b := range nativeBrowsers {
		if !b.manifestFileFor(runtime.GOOS) {
			continue
		}
		m, ok := linkedManifest(b)
		switch {
		case ok:
			path, _ := m["path"].(string)
			state := "linked"
			if _, err := os.Stat(path); err != nil {
				state = "linked to a pm that no longer exists (" + path + "). Run 'pm extension link' again"
			} else if binary != "" && path != binary {
				state = "linked to " + path
			}
			rows = append(rows, row{b.name, state})
			linked++
		case b.installed():
			rows = append(rows, row{b.name, "not linked"})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].state == "linked" && rows[j].state != "linked" })
	if len(rows) == 0 {
		fmt.Println("No Chromium browser found.")
	}
	for _, r := range rows {
		statusLine(r.name, r.state)
	}
	if c, ok := readNativeHostConfig(); ok {
		statusLine("Linked vault", c.Vault)
		statusLine("Linked on", time.UnixMilli(c.Linked).Format("Jan 2, 2006 15:04"))
	}

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 3 * time.Second}
	var info struct {
		Name     string `json:"name"`
		Mode     string `json:"mode"`
		Version  string `json:"version"`
		API      int    `json:"api"`
		Unlocked bool   `json:"unlocked"`
	}
	listening := false
	if resp, err := client.Get(base + "/api/info"); err == nil {
		err = json.NewDecoder(resp.Body).Decode(&info)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || info.Name != "APM" {
			statusLine("Right now", fmt.Sprintf("something other than APM is listening on 127.0.0.1:%d", port))
			return 1
		}
		listening = true
	}
	token, _, haveToken := readBridgeToken(bridgeTokenFile())
	switch {
	case listening && info.Mode == "serve":
		statusLine("Right now", "the extension uses 'pm extension serve'")
	case listening:
		statusLine("Right now", "the extension uses the APM app")
	case linked > 0:
		statusLine("Right now", "the APM app is closed, so the browser starts pm")
	default:
		statusLine("Right now", fmt.Sprintf("nothing is listening on 127.0.0.1:%d and no browser is linked", port))
		fmt.Println("\nRun 'pm extension link' to use the extension without the APM app.")
		return 1
	}
	if !listening {
		if haveToken {
			statusLine("Token", bridgeTokenFingerprint(token)+" (fingerprint)")
		}
		return 0
	}

	statusLine("Listening", fmt.Sprintf("127.0.0.1:%d", port))
	statusLine("Version", fmt.Sprintf("%s (bridge API %d)", info.Version, info.API))
	vaultState := "locked"
	if info.Unlocked {
		vaultState = "unlocked"
	}
	if !haveToken {
		statusLine("Vault", vaultState)
		statusLine("Token", "none yet. Run 'pm extension token' to create one.")
		return 0
	}
	req, _ := http.NewRequest("GET", base+"/api/status", nil)
	req.Header.Set("x-apm-token", token)
	req.Header.Set("x-apm-client", "pm extension status")
	sresp, err := client.Do(req)
	if err != nil {
		statusLine("Vault", vaultState)
		statusLine("Token", fmt.Sprintf("%s (the status request failed: %v)", bridgeTokenFingerprint(token), err))
		return 1
	}
	defer sresp.Body.Close()
	if sresp.StatusCode == http.StatusUnauthorized {
		statusLine("Vault", vaultState)
		statusLine("Token", bridgeTokenFingerprint(token)+" does not match the running bridge. It may use a different config directory.")
		return 1
	}
	var st struct {
		Unlocked bool `json:"unlocked"`
		Readonly bool `json:"readonly"`
		Items    int  `json:"items"`
	}
	_ = json.NewDecoder(sresp.Body).Decode(&st)
	switch {
	case st.Unlocked && st.Readonly:
		statusLine("Vault", fmt.Sprintf("unlocked, read-only, %d items", st.Items))
	case st.Unlocked:
		statusLine("Vault", fmt.Sprintf("unlocked, %d items", st.Items))
	default:
		statusLine("Vault", "locked")
	}
	statusLine("Token", bridgeTokenFingerprint(token)+" (fingerprint)")
	return 0
}

func newExtensionHostCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "host [origin]",
		Short:  "Run the native messaging host the browser starts",
		Hidden: true,
		Args:   cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			origin := "chrome-extension://" + apmExtensionID + "/"
			if len(args) == 1 {
				origin = args[0]
			}
			os.Exit(runNativeHost(origin))
		},
	}
}
