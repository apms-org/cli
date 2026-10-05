package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aaravmaloo/apm/internal/tty"
	"golang.org/x/term"
)

// All keyboard input in package main goes through internal/tty, which reads
// stdin with one shared reader and decodes keys the same way in every
// terminal. These helpers apply the CLI's policy on top of it:
//
//   - Esc at a plain prompt cancels the command: the terminal is restored,
//     "Cancelled." goes to stderr and pm exits 1.
//   - Ctrl+C restores the terminal and exits 130.
//   - Without a terminal (pipes, tests) a prompt reads one line, and EOF reads
//     as an empty answer.

// exitInterrupted restores the terminal and exits as an interrupted
// program would.
func exitInterrupted() {
	tty.Restore()
	tty.Exit(130)
}

// exitCancelled ends the command after Esc at a prompt.
func exitCancelled(msg string) {
	tty.Restore()
	if msg == "" {
		msg = "Cancelled."
	}
	fmt.Fprintln(os.Stderr, msg)
	tty.Exit(1)
}

// exitOnInputError exits for Ctrl+C and for hidden input the terminal cannot
// provide. Esc (tty.ErrCanceled) and other errors are returned to the caller.
func exitOnInputError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, tty.ErrInterrupted):
		exitInterrupted()
	case errors.Is(err, tty.ErrNoHiddenInput):
		tty.Restore()
		fmt.Fprintln(os.Stderr, err.Error())
		tty.Exit(1)
	}
	return err
}

// readLineOpts reads a line and returns tty.ErrCanceled on Esc so the caller
// can decide what Esc means there. EOF reads as an empty line.
func readLineOpts(opts tty.LineOptions) (string, error) {
	s, err := tty.ReadLine(opts)
	if err = exitOnInputError(err); err != nil {
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		return "", err
	}
	return s, nil
}

// promptLine prints prompt and reads one trimmed line. Esc cancels the
// command. EOF and read errors return "".
func promptLine(prompt string) string {
	s, err := readLineOpts(tty.LineOptions{Prompt: prompt})
	if errors.Is(err, tty.ErrCanceled) {
		exitCancelled("")
	}
	return s
}

// readInput reads one trimmed line after a prompt the caller printed.
func readInput() string {
	return promptLine("")
}

// promptPassword prints prompt and reads a line without echo, ending the line
// itself. Esc cancels the command. Without a terminal a blank line or EOF is
// an error, as it always was.
func promptPassword(prompt string) (string, error) {
	interactive := tty.Interactive()
	s, err := tty.ReadLine(tty.LineOptions{Prompt: prompt, Hidden: true})
	if !interactive {
		fmt.Println() // the line ends here, as the echo would have ended it
	}
	if err = exitOnInputError(err); err != nil {
		if errors.Is(err, tty.ErrCanceled) {
			exitCancelled("")
		}
		if !interactive {
			return "", fmt.Errorf("EOF or empty input")
		}
		return "", err
	}
	if !interactive && s == "" {
		return "", fmt.Errorf("EOF or empty input")
	}
	return s, nil
}

// readPassword reads a hidden line after a prompt the caller printed, and
// ends the line.
func readPassword() (string, error) {
	return promptPassword("")
}

// promptConfirm prints question and reads a yes/no answer: one key on a
// terminal (y, n, Enter for the default, Esc for no), a line otherwise (blank
// or EOF for the default).
func promptConfirm(question string, defaultYes bool) bool {
	fmt.Print(question)
	ok, err := tty.Confirm(defaultYes)
	if err = exitOnInputError(err); err != nil {
		return defaultYes && errors.Is(err, io.EOF)
	}
	return ok
}

// confirmOrCancel asks a yes/no question where Esc must not mean either
// answer: on a terminal y/n answer, Enter takes the default and Esc returns
// cancelled. Without a terminal it reads a line like promptConfirm.
func confirmOrCancel(question string, defaultYes bool) (yes, cancelled bool) {
	fmt.Print(question)
	if !tty.Interactive() {
		ok, err := tty.Confirm(defaultYes)
		if err != nil {
			return defaultYes && errors.Is(err, io.EOF), false
		}
		return ok, false
	}
	restore, err := tty.EnterRaw()
	if err != nil {
		return false, true
	}
	defer restore()
	echo := func(s string) {
		if stdoutIsTerminal() {
			tty.Printf("%s\n", s)
		}
	}
	for {
		k, err := tty.ReadKey()
		if err != nil {
			echo("")
			_ = exitOnInputError(err)
			return false, true
		}
		switch {
		case k.IsRune('y'), k.IsRune('Y'):
			echo("y")
			return true, false
		case k.IsRune('n'), k.IsRune('N'):
			echo("n")
			return false, false
		case k.Type == tty.KeyEnter:
			if defaultYes {
				echo("y")
			} else {
				echo("n")
			}
			return defaultYes, false
		case k.Type == tty.KeyEsc:
			echo("")
			return false, true
		}
	}
}

// pressEnterToContinue waits before going back to a screen. Enter, Esc,
// Space and q all continue.
func pressEnterToContinue() {
	fmt.Print("\nPress Enter to continue...")
	_ = exitOnInputError(tty.Pause())
}

// selectOption shows options and returns the index picked; Esc returns
// tty.ErrCanceled.
func selectOption(opts tty.SelectOptions) (int, error) {
	i, err := tty.Select(opts)
	return i, exitOnInputError(err)
}

// stdoutIsTerminal reports whether tty echoes and ends lines on stdout.
func stdoutIsTerminal() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// rawScreen keeps the terminal raw for a full-screen view and hands it back
// in cooked mode for sub-screens that print and prompt normally.
type rawScreen struct {
	restore func()
}

// enter makes the terminal raw. It also installs the handler that restores
// the terminal on SIGINT/SIGTERM/SIGHUP, which is only done here, by
// full-screen views, so that server modes keep their own signal handling.
func (s *rawScreen) enter() error {
	tty.InstallSignalHandler()
	restore, err := tty.EnterRaw()
	if err != nil {
		return err
	}
	s.restore = restore
	return nil
}

// leave returns the terminal to cooked mode.
func (s *rawScreen) leave() {
	if s.restore != nil {
		s.restore()
		s.restore = nil
	}
}

// cooked runs fn with the terminal in cooked mode, then makes it raw again.
func (s *rawScreen) cooked(fn func()) {
	s.leave()
	fn()
	_ = s.enter()
}
