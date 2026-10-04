package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	src "github.com/aaravmaloo/apm/src"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// lockPolicy is when an unlocked vault locks itself. It lives in the vault's
// desktop settings, so the app, pm and the browser extension share one policy.
// A zero Idle or Max means never.
type lockPolicy struct {
	Idle  time.Duration
	Max   time.Duration
	Sleep bool
}

func defaultLockPolicy() lockPolicy {
	return lockPolicy{
		Idle:  settingMinutes(defaultDesktopSettings["inactivity"], 15*time.Minute),
		Max:   settingMinutes(defaultDesktopSettings["sessionTimeout"], time.Hour),
		Sleep: settingBool(defaultDesktopSettings["lockOnSleep"], true),
	}
}

func lockPolicyOf(v *src.Vault) lockPolicy {
	p := defaultLockPolicy()
	if v == nil || v.Desktop == nil || v.Desktop.Settings == nil {
		return p
	}
	st := v.Desktop.Settings
	if x, ok := st["inactivity"]; ok {
		p.Idle = settingMinutes(x, p.Idle)
	}
	if x, ok := st["sessionTimeout"]; ok {
		p.Max = settingMinutes(x, p.Max)
	}
	if x, ok := st["lockOnSleep"]; ok {
		p.Sleep = settingBool(x, p.Sleep)
	}
	return p
}

func (p lockPolicy) apply(v *src.Vault) {
	if v.Desktop == nil {
		v.Desktop = &src.DesktopState{}
	}
	if v.Desktop.Settings == nil {
		v.Desktop.Settings = map[string]any{}
	}
	v.Desktop.Settings["inactivity"] = strconv.Itoa(int(p.Idle / time.Minute))
	v.Desktop.Settings["sessionTimeout"] = strconv.Itoa(int(p.Max / time.Minute))
	v.Desktop.Settings["lockOnSleep"] = p.Sleep
}

func (p lockPolicy) never() bool {
	return p.Idle == 0 && p.Max == 0
}

// summary reads like the app's Security page: "after 15 minutes idle, 1 hour
// at most, and on sleep".
func (p lockPolicy) summary() string {
	var parts []string
	if p.Idle > 0 {
		parts = append(parts, "after "+lockDurationText(p.Idle)+" idle")
	}
	if p.Max > 0 {
		parts = append(parts, lockDurationText(p.Max)+" at most")
	}
	if p.Sleep {
		parts = append(parts, "on sleep")
	}
	switch len(parts) {
	case 0:
		return "never on its own"
	case 1:
		return parts[0]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
}

// settingMinutes reads a minutes value the app stores as a string ("15") or a
// JSON number. "0" is never. Anything unreadable falls back to def.
func settingMinutes(v any, def time.Duration) time.Duration {
	var n float64
	switch x := v.(type) {
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return def
		}
		n = f
	case float64:
		n = x
	case int:
		n = float64(x)
	case int64:
		n = float64(x)
	default:
		return def
	}
	if n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return def
	}
	return time.Duration(n * float64(time.Minute))
}

func settingBool(v any, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		if b, err := strconv.ParseBool(strings.TrimSpace(x)); err == nil {
			return b
		}
	}
	return def
}

// parseLockDuration accepts "never", "off" or "0" for never, a Go duration
// ("30m", "4h") or a bare number of minutes ("15"). Values round up to whole
// minutes, because the app stores minutes.
func parseLockDuration(s string) (time.Duration, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "never", "off", "none", "0":
		return 0, nil
	case "":
		return 0, fmt.Errorf("give a duration like 15m or 4h, or never")
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Minute
	} else {
		parsed, perr := time.ParseDuration(v)
		if perr != nil {
			return 0, fmt.Errorf("%q is not a duration. Use something like 15m, 4h or never", s)
		}
		d = parsed
	}
	if d < 0 {
		return 0, fmt.Errorf("%q is negative. Use something like 15m, 4h or never", s)
	}
	if d == 0 {
		return 0, nil
	}
	if d%time.Minute != 0 {
		d = d.Truncate(time.Minute) + time.Minute
	}
	if d > 30*24*time.Hour {
		return 0, fmt.Errorf("%q is longer than 30 days. Use never to turn it off", s)
	}
	return d, nil
}

func parseOnOff(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "yes", "true", "1":
		return true, nil
	case "off", "no", "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("%q is not on or off", s)
}

func lockDurationText(d time.Duration) string {
	if d <= 0 {
		return "never"
	}
	m := int(d / time.Minute)
	if m > 24*60 && m%(24*60) == 0 {
		return plural(m/(24*60), "day")
	}
	if m%60 == 0 {
		return plural(m/60, "hour")
	}
	return plural(m, "minute")
}

// startSession opens the pm session other pm commands reuse, on this policy.
func (p lockPolicy) startSession(password string, readonly bool) error {
	return src.CreateLockingSession(password, p.Max, readonly, p.Idle, p.Sleep)
}

// unlockedLine tells what the pm session started by startSession does.
func (p lockPolicy) unlockedLine() string {
	p.Sleep = p.Sleep && src.SleepLockSupported()
	if p.never() && !p.Sleep {
		return "Vault unlocked. It stays unlocked until you run 'pm lock'."
	}
	return "Vault unlocked. It locks " + p.summary() + "."
}

func newAutolockCmd() *cobra.Command {
	var idle, max, sleep string
	cmd := &cobra.Command{
		Use:   "autolock",
		Short: "Show or change when the vault locks itself",
		Long: "Show or change when the vault locks itself. The policy is saved in the vault and shared by the desktop app, pm sessions and the browser extension.\n\n" +
			"Durations take Go syntax (15m, 4h) or a number of minutes. Use never to turn a limit off.",
		Example: "  pm autolock\n  pm autolock --idle 30m --max 8h\n  pm autolock --idle never --max never\n  pm autolock --sleep off",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runAutolock(cmd, idle, max, sleep))
		},
	}
	cmd.Flags().StringVar(&idle, "idle", "", "Lock after this long without use (15m, 1h, never)")
	cmd.Flags().StringVar(&max, "max", "", "Lock after this long even while in use (1h, 8h, never)")
	cmd.Flags().StringVar(&sleep, "sleep", "", "Lock when the computer sleeps (on or off)")
	return cmd
}

func runAutolock(cmd *cobra.Command, idleFlag, maxFlag, sleepFlag string) int {
	change := cmd.Flags().Changed("idle") || cmd.Flags().Changed("max") || cmd.Flags().Changed("sleep")
	pass, v, readonly, err := src_unlockVault()
	if err != nil {
		color.Red("%v", err)
		return 1
	}
	cur := lockPolicyOf(v)
	if !change {
		printLockPolicy(cur)
		return 0
	}
	if readonly {
		color.Red("This session is read-only. Unlock with full access to change auto-lock.")
		return 1
	}
	next := cur
	if cmd.Flags().Changed("idle") {
		d, err := parseLockDuration(idleFlag)
		if err != nil {
			color.Red("--idle: %v", err)
			return 1
		}
		next.Idle = d
	}
	if cmd.Flags().Changed("max") {
		d, err := parseLockDuration(maxFlag)
		if err != nil {
			color.Red("--max: %v", err)
			return 1
		}
		next.Max = d
	}
	if cmd.Flags().Changed("sleep") {
		b, err := parseOnOff(sleepFlag)
		if err != nil {
			color.Red("--sleep: %v", err)
			return 1
		}
		next.Sleep = b
	}
	if next == cur {
		fmt.Println("Nothing changed.")
		printLockPolicy(cur)
		return 0
	}
	next.apply(v)
	if err := saveCLIVault(v, pass); err != nil {
		color.Red("Could not save the vault: %v", err)
		return 1
	}
	src.LogAction("SETTINGS_CHANGED", "inactivity, sessionTimeout, lockOnSleep (pm autolock)")
	if sess, err := src.PeekSession(); err == nil && sess != nil {
		_ = next.startSession(pass, sess.ReadOnly)
	}
	color.Green("Auto-lock updated.")
	printLockPolicy(next)
	return 0
}

func printLockPolicy(p lockPolicy) {
	fmt.Printf("Lock after inactivity:  %s\n", lockDurationText(p.Idle))
	fmt.Printf("Maximum session:        %s\n", lockDurationText(p.Max))
	sleep := "on"
	if !p.Sleep {
		sleep = "off"
	}
	fmt.Printf("Lock on sleep:          %s\n", sleep)
	fmt.Println("Applies to the desktop app, pm sessions and the browser extension.")
	switch {
	case p.never() && !p.Sleep:
		color.Yellow("\nWarning: the vault never locks on its own. It stays unlocked until you run 'pm lock', quit the app or close the browser. Anyone who can use this computer meanwhile can read every secret.")
	case p.never():
		color.Yellow("\nWarning: the vault only locks when the computer sleeps or you lock it. Anyone who can use this computer while it is awake can read every secret.")
	case p.Idle == 0:
		color.Yellow("\nWarning: the vault no longer locks when you step away. It stays unlocked for up to %s.", lockDurationText(p.Max))
	case p.Max == 0:
		color.Yellow("\nWarning: there is no maximum session. As long as it is in use within %s, the vault stays unlocked.", lockDurationText(p.Idle))
	}
}
