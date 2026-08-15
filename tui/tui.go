/*
* Contains TUI logic
*
* - Rich display of status (sender/receiver, in snadbox, TCP connected)
* - Loading bar for sending/receiving files
* - Hints for keyboard shortcuts
* - Accept arguments: multiple files as arguments, multiple files as multiple commands
*
 */

package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"snad/snadbox"
)

type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	Select key.Binding
	Quit   key.Binding
}

var keys = keyMap{
	Up:     key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:   key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Select: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "send")),
	Quit:   key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

var (
	titleStyle          = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	identityStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	sectionStyle        = lipgloss.NewStyle().Bold(true).Underline(true)
	selectedMemberStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	dimStyle            = lipgloss.NewStyle().Faint(true)
	errorStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

// transferKey identifies one in-flight or completed file transfer.
type transferKey struct {
	Peer      string
	File      string
	Direction snadbox.Direction
}

type transferState struct {
	file    string
	peer    string
	dir     snadbox.Direction
	bar     progress.Model
	failed  bool
	skipped bool
	err     error
}

// Model is the bubbletea model driving the whole snad TUI: a lobby of
// discovered peers plus a live view of in-flight transfers, all fed by
// events emitted from snadbox's background goroutines.
type Model struct {
	identity snadbox.Identity
	role     string
	files    []string
	sender   *snadbox.Sender
	events   chan interface{}

	members []snadbox.Member
	cursor  int

	transfers map[transferKey]*transferState
	order     []transferKey

	quitting bool
}

// New builds the initial model. files is the set of paths staged to send
// once a peer is picked (empty means pure receive mode).
func New(identity snadbox.Identity, files []string, sender *snadbox.Sender, events chan interface{}) Model {
	role := "receiver"
	if len(files) > 0 {
		role = "sender"
	}
	return Model{
		identity:  identity,
		role:      role,
		files:     files,
		sender:    sender,
		events:    events,
		transfers: make(map[transferKey]*transferState),
	}
}

type eventMsg struct{ msg interface{} }

func waitForEvent(events chan interface{}) tea.Cmd {
	return func() tea.Msg {
		return eventMsg{msg: <-events}
	}
}

func (m Model) Init() tea.Cmd {
	return waitForEvent(m.events)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Quit):
			m.quitting = true
			return m, tea.Quit
		case key.Matches(msg, keys.Up):
			if m.cursor > 0 {
				m.cursor--
			}
		case key.Matches(msg, keys.Down):
			if m.cursor < len(m.members)-1 {
				m.cursor++
			}
		case key.Matches(msg, keys.Select):
			if m.role == "sender" && m.cursor < len(m.members) {
				peer := m.members[m.cursor]
				go m.sender.Send(m.identity, peer, m.files, m.events)
			}
		}
		return m, nil

	case eventMsg:
		cmd := m.handleEvent(msg.msg)
		return m, tea.Batch(cmd, waitForEvent(m.events))

	case progress.FrameMsg:
		var cmds []tea.Cmd
		for _, k := range m.order {
			t := m.transfers[k]
			updated, cmd := t.bar.Update(msg)
			if pm, ok := updated.(progress.Model); ok {
				t.bar = pm
			}
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

// handleEvent applies one snadbox event to the model, returning a tea.Cmd
// when a progress bar animation needs to keep ticking.
func (m *Model) handleEvent(raw interface{}) tea.Cmd {
	switch e := raw.(type) {
	case snadbox.MemberJoined:
		m.members = append(m.members, e.Member)
		sort.Slice(m.members, func(i, j int) bool { return m.members[i].Name < m.members[j].Name })

	case snadbox.MemberLeft:
		for i, mem := range m.members {
			if mem.Name == e.Name {
				m.members = append(m.members[:i], m.members[i+1:]...)
				break
			}
		}
		if m.cursor >= len(m.members) && m.cursor > 0 {
			m.cursor = len(m.members) - 1
		}

	case snadbox.TransferStarted:
		k := transferKey{Peer: e.Peer, File: e.File, Direction: e.Direction}
		bar := progress.New(progress.WithDefaultGradient())
		m.transfers[k] = &transferState{file: e.File, peer: e.Peer, dir: e.Direction, bar: bar}
		m.order = append(m.order, k)

	case snadbox.TransferProgress:
		k := transferKey{Peer: e.Peer, File: e.File, Direction: e.Direction}
		if t, ok := m.transfers[k]; ok {
			pct := 0.0
			if e.Total > 0 {
				pct = float64(e.Sent) / float64(e.Total)
			}
			return t.bar.SetPercent(pct)
		}

	case snadbox.TransferDone:
		k := transferKey{Peer: e.Peer, File: e.File, Direction: e.Direction}
		if t, ok := m.transfers[k]; ok {
			return t.bar.SetPercent(1.0)
		}

	case snadbox.TransferSkipped:
		k := transferKey{Peer: e.Peer, File: e.File, Direction: e.Direction}
		bar := progress.New(progress.WithDefaultGradient())
		t := &transferState{file: e.File, peer: e.Peer, dir: e.Direction, bar: bar, skipped: true}
		m.transfers[k] = t
		m.order = append(m.order, k)
		return t.bar.SetPercent(1.0)

	case snadbox.TransferError:
		k := transferKey{Peer: e.Peer, File: e.File, Direction: e.Direction}
		t, ok := m.transfers[k]
		if !ok {
			t = &transferState{file: e.File, peer: e.Peer, dir: e.Direction, bar: progress.New(progress.WithDefaultGradient())}
			m.transfers[k] = t
			m.order = append(m.order, k)
		}
		t.failed = true
		t.err = e.Err
	}
	return nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder

	fmt.Fprintf(&b, "%s  you are %s\n\n", titleStyle.Render("snad"), identityStyle.Render(m.identity.Name))

	b.WriteString(sectionStyle.Render("snadbox members"))
	b.WriteString("\n")
	if len(m.members) == 0 {
		b.WriteString(dimStyle.Render("  (searching for peers...)"))
		b.WriteString("\n")
	}
	for i, mem := range m.members {
		cursor := "  "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			cursor = "> "
			style = selectedMemberStyle
		}
		b.WriteString(style.Render(cursor + mem.Name))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if len(m.order) > 0 {
		b.WriteString(sectionStyle.Render("transfers"))
		b.WriteString("\n")
		for _, k := range m.order {
			b.WriteString(renderTransfer(m.transfers[k]))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	help := "↑/↓ choose peer"
	if m.role == "sender" {
		help += " • enter send"
	}
	help += " • q quit"
	b.WriteString(dimStyle.Render(help))

	return b.String()
}

func renderTransfer(t *transferState) string {
	arrow := "→"
	if t.dir == snadbox.DirectionRecv {
		arrow = "←"
	}
	label := fmt.Sprintf("%s %s %s", t.file, arrow, t.peer)

	switch {
	case t.failed:
		msg := "failed"
		if t.err != nil {
			msg = "failed: " + t.err.Error()
		}
		return fmt.Sprintf("  %-30s %s", label, errorStyle.Render(msg))
	case t.skipped:
		return fmt.Sprintf("  %-30s %s", label, dimStyle.Render("skipped (already have it)"))
	default:
		return fmt.Sprintf("  %-30s %s", label, t.bar.View())
	}
}
