package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aaravmaloo/apm/internal/tty"
	src "github.com/aaravmaloo/apm/src"
)

// noteEditorMaxUndo caps the size of the undo/redo stacks.
const noteEditorMaxUndo = 200

// noteSnap is a snapshot of editor state used by undo/redo.
type noteSnap struct {
	value string
	line  int
	col   int
}

// noteEditorModel is the Bubble Tea model backing the APM note editor.
type noteEditorModel struct {
	ta         textarea.Model
	title      string
	space      string
	initial    string
	modified   bool
	result     string
	cancelled  bool
	done       bool
	confirming bool
	status     string
	undo       []noteSnap
	redo       []noteSnap
	width      int
	height     int
}

// Editor chrome styles.
var (
	noteEditorAccent = lipgloss.AdaptiveColor{Light: "27", Dark: "81"}
	noteEditorMuted  = lipgloss.AdaptiveColor{Light: "240", Dark: "243"}
	noteEditorWarn   = lipgloss.AdaptiveColor{Light: "130", Dark: "214"}

	noteEditorTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.AdaptiveColor{Light: "17", Dark: "231"}).
				Background(noteEditorAccent).
				Padding(0, 1)

	noteEditorNameStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(noteEditorAccent)

	noteEditorMetaStyle = lipgloss.NewStyle().
				Foreground(noteEditorMuted)

	noteEditorBoxStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.AdaptiveColor{Light: "250", Dark: "240"}).
				Padding(0, 1)

	noteEditorStatusStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "235", Dark: "252"}).
				Background(lipgloss.AdaptiveColor{Light: "250", Dark: "236"}).
				Padding(0, 1)

	noteEditorWarnStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(noteEditorWarn)

	noteEditorCleanStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "28", Dark: "78"})

	noteEditorHintKeyStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.AdaptiveColor{Light: "238", Dark: "246"})

	noteEditorHintStyle = lipgloss.NewStyle().
				Foreground(noteEditorMuted)
)

// newNoteEditorModel builds the editor with the given title, vault space and
// initial content.
func newNoteEditorModel(title, space, initial string) noteEditorModel {
	ta := textarea.New()
	ta.Placeholder = "Start writing…  (Ctrl+S save · Esc cancel)"
	ta.Prompt = "│ "
	ta.CharLimit = 0
	ta.ShowLineNumbers = true
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle().
		Background(lipgloss.AdaptiveColor{Light: "253", Dark: "238"})
	ta.FocusedStyle.CursorLineNumber = lipgloss.NewStyle().
		Bold(true).
		Foreground(noteEditorAccent)
	ta.BlurredStyle = ta.FocusedStyle

	m := noteEditorModel{
		ta:      ta,
		title:   title,
		space:   space,
		initial: initial,
		width:   80,
		height:  24,
	}
	m.ta.Focus()
	m.ta.SetValue(initial)
	m.ta.SetWidth(noteEditorTextAreaWidth(m.width))
	m.ta.SetHeight(noteEditorTextAreaHeight(m.height, m.width))
	return m
}

// Init starts the cursor blink.
func (m noteEditorModel) Init() tea.Cmd {
	return m.ta.Focus()
}

// Update handles keys, window resizes, and textarea events.
func (m noteEditorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ta.SetWidth(noteEditorTextAreaWidth(msg.Width))
		m.ta.SetHeight(noteEditorTextAreaHeight(msg.Height, msg.Width))
		return m, nil

	case tea.KeyMsg:
		if m.confirming {
			switch msg.String() {
			case "esc", "ctrl+c":
				m.cancelled = true
				m.done = true
				return m, tea.Quit
			}
			// Any other key dismisses the prompt and is applied normally.
			m.confirming = false
			m.status = ""
		}

		switch msg.String() {
		case "ctrl+s":
			m.result = m.ta.Value()
			m.done = true
			return m, tea.Quit
		case "esc", "ctrl+c":
			if m.modified {
				m.confirming = true
				m.status = "Unsaved changes — Esc again to discard, any other key to continue"
			} else {
				m.cancelled = true
				m.done = true
				return m, tea.Quit
			}
			return m, nil
		case "ctrl+z":
			m.undoEdit()
			return m, nil
		case "ctrl+y":
			m.redoEdit()
			return m, nil
		}

		prev := m.snap()
		updated, cmd := m.ta.Update(msg)
		m.ta = updated
		if m.ta.Value() != prev.value {
			m.pushUndo(prev)
			m.modified = m.ta.Value() != m.initial
			m.status = ""
		}
		return m, cmd
	}

	updated, cmd := m.ta.Update(msg)
	m.ta = updated
	return m, cmd
}

// snap captures the current value and cursor position.
func (m noteEditorModel) snap() noteSnap {
	return noteSnap{value: m.ta.Value(), line: m.ta.Line(), col: m.ta.LineInfo().ColumnOffset}
}

// pushUndo records a pre-edit snapshot and clears the redo stack.
func (m *noteEditorModel) pushUndo(s noteSnap) {
	m.undo = append(m.undo, s)
	if len(m.undo) > noteEditorMaxUndo {
		m.undo = append([]noteSnap(nil), m.undo[len(m.undo)-noteEditorMaxUndo:]...)
	}
	m.redo = nil
}

// undoEdit restores the most recent pre-edit snapshot.
func (m *noteEditorModel) undoEdit() {
	if len(m.undo) == 0 {
		m.status = "Nothing to undo"
		return
	}
	m.redo = append(m.redo, m.snap())
	last := m.undo[len(m.undo)-1]
	m.undo = m.undo[:len(m.undo)-1]
	m.restore(last)
	m.modified = m.ta.Value() != m.initial
	m.status = "Undo"
}

// redoEdit re-applies the most recently undone edit.
func (m *noteEditorModel) redoEdit() {
	if len(m.redo) == 0 {
		m.status = "Nothing to redo"
		return
	}
	m.undo = append(m.undo, m.snap())
	last := m.redo[len(m.redo)-1]
	m.redo = m.redo[:len(m.redo)-1]
	m.restore(last)
	m.modified = m.ta.Value() != m.initial
	m.status = "Redo"
}

// restore rewinds the editor to a snapshot and repositions the cursor.
func (m *noteEditorModel) restore(s noteSnap) {
	m.ta.SetValue(s.value)
	for m.ta.Line() > s.line {
		m.ta.CursorUp()
	}
	for m.ta.Line() < s.line {
		m.ta.CursorDown()
	}
	m.ta.SetCursor(s.col)
}

// View renders the full editor screen.
func (m noteEditorModel) View() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	// Header: editor badge + note name + space metadata.
	header := lipgloss.JoinHorizontal(lipgloss.Top,
		noteEditorTitleStyle.Render("APM NOTE EDITOR"),
		" ",
		noteEditorNameStyle.Render(truncateNoteText(m.title, noteEditorNameMax(w))),
	)
	if m.space != "" {
		header = lipgloss.JoinHorizontal(lipgloss.Top, header,
			noteEditorMetaStyle.Render("   ·   space: "+truncateNoteText(m.space, noteEditorNameMax(w))))
	}
	header = noteEditorStatusStyle.Width(w).MaxWidth(w).Render(header)

	// Body: the textarea inside a rounded frame.
	body := noteEditorBoxStyle.Render(m.ta.View())

	// Status bar: position/counts on the left, save state on the right.
	left := m.statusText()
	right := m.statusRight()
	status := lipgloss.JoinHorizontal(lipgloss.Left, left, "   ", right)
	status = noteEditorStatusStyle.Width(w).MaxWidth(w).Render(status)

	// Footer: keybinding hints split across two rows.
	footer := noteEditorHintStyle.MaxWidth(w).Render(m.footerHints())
	if w >= 60 {
		footer += "\n" + noteEditorHintStyle.MaxWidth(w).Render(m.footerHintsExtended())
	}

	return header + "\n" + body + "\n" + status + "\n" + footer
}

// statusText is the left-hand side of the status bar.
func (m noteEditorModel) statusText() string {
	if m.status != "" {
		return m.status
	}
	li := m.ta.LineInfo()
	words := len(strings.Fields(m.ta.Value()))
	return fmt.Sprintf("Ln %d, Col %d   ·   %d chars   ·   %d words",
		m.ta.Line()+1, li.ColumnOffset+1, m.ta.Length(), words)
}

// statusRight is the right-hand side of the status bar.
func (m noteEditorModel) statusRight() string {
	if m.modified {
		return noteEditorWarnStyle.Render("● modified")
	}
	return noteEditorCleanStyle.Render("● clean")
}

// footerHints lists the essential keybindings.
func (m noteEditorModel) footerHints() string {
	hints := []string{
		"^S save", "Esc cancel", "^Z undo", "^Y redo", "^V paste", "^W del-word", "^T swap",
	}
	return renderNoteEditorHints(hints)
}

// footerHintsExtended lists the secondary keybindings.
func (m noteEditorModel) footerHintsExtended() string {
	hints := []string{
		"^K del-to-end", "^U del-to-start", "^A/^E line start/end", "^D del-char", "alt+U/L/C word case",
	}
	return renderNoteEditorHints(hints)
}

// renderNoteEditorHints joins hint labels with separators.
func renderNoteEditorHints(hints []string) string {
	var b strings.Builder
	for i, h := range hints {
		if i > 0 {
			b.WriteString("   ")
		}
		b.WriteString(noteEditorHintKeyStyle.Render(h))
	}
	return b.String()
}

// noteEditorTextAreaWidth returns the textarea width given the terminal width.
func noteEditorTextAreaWidth(w int) int {
	if w <= 0 {
		w = 80
	}
	aw := w - 4
	if aw < 10 {
		aw = 10
	}
	return aw
}

// noteEditorTextAreaHeight returns the textarea height given the terminal
// height and width. The footer collapses to a single row on narrow terminals.
func noteEditorTextAreaHeight(h, w int) int {
	if h <= 0 {
		h = 24
	}
	footerRows := 2
	if w < 60 {
		footerRows = 1
	}
	ah := h - 4 - footerRows
	if ah < 3 {
		ah = 3
	}
	return ah
}

// noteEditorNameMax returns how many columns the note name may occupy.
func noteEditorNameMax(w int) int {
	m := w / 3
	if m < 8 {
		m = 8
	}
	return m
}

// truncateNoteText truncates s with an ellipsis to max runes.
func truncateNoteText(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max < 1 {
		max = 1
	}
	return string(r[:max]) + "…"
}

// captureNoteContent opens the full-screen note editor. In non-interactive
// contexts it falls back to reading plain lines until an empty line is sent.
func captureNoteContent(vault *src.Vault, title, initial string) (string, error) {
	if !tty.Interactive() {
		if strings.TrimSpace(initial) != "" {
			return initial, nil
		}
		fmt.Println("Content (end with empty line):")
		var contentLines []string
		for {
			line := readInput()
			if line == "" {
				break
			}
			contentLines = append(contentLines, line)
		}
		return strings.Join(contentLines, "\n"), nil
	}

	if title == "" {
		title = "Untitled Note"
	}
	space := ""
	if vault != nil {
		space = vault.CurrentSpace
	}

	model := newNoteEditorModel(title, space, initial)
	// Hand bubbletea a cooked terminal with no keys left over from the
	// prompts before it.
	tty.Restore()
	tty.Discard()
	program := tea.NewProgram(model, tea.WithAltScreen())
	final, err := program.Run()
	tty.Discard()
	if err != nil {
		return "", fmt.Errorf("note editor error: %w", err)
	}
	fm, ok := final.(noteEditorModel)
	if !ok || !fm.done {
		return "", fmt.Errorf("note edit cancelled")
	}
	if fm.cancelled {
		return "", fmt.Errorf("note edit cancelled")
	}
	return fm.result, nil
}
