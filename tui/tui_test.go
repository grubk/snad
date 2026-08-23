package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"snad/snadbox"
)

func newTestModel(role string) Model {
	files := []string{}
	if role == "sender" {
		files = []string{"file.txt"}
	}
	return New(snadbox.Identity{Name: "test-identity"}, files, nil, make(chan interface{}))
}

func keyMsg(runes ...rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: runes}
}

func TestCursorMovementStaysWithinBounds(t *testing.T) {
	m := newTestModel("receiver")
	m.members = []snadbox.Member{{Name: "a"}, {Name: "b"}, {Name: "c"}}

	updated, _ := m.Update(keyMsg('j'))
	m = updated.(Model)
	if m.cursor != 1 {
		t.Fatalf("expected cursor at 1 after one down, got %d", m.cursor)
	}

	for i := 0; i < 5; i++ {
		updated, _ = m.Update(keyMsg('j'))
		m = updated.(Model)
	}
	if m.cursor != len(m.members)-1 {
		t.Fatalf("cursor should clamp at bottom, got %d want %d", m.cursor, len(m.members)-1)
	}

	for i := 0; i < 5; i++ {
		updated, _ = m.Update(keyMsg('k'))
		m = updated.(Model)
	}
	if m.cursor != 0 {
		t.Fatalf("cursor should clamp at top, got %d", m.cursor)
	}
}

func TestQuitSetsQuittingAndReturnsQuitCmd(t *testing.T) {
	m := newTestModel("receiver")

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = updated.(Model)
	if !m.quitting {
		t.Fatal("expected quitting to be set after ctrl+c")
	}
	if cmd == nil {
		t.Fatal("expected a non-nil tea.Cmd (tea.Quit) after quitting")
	}
}

func TestMemberJoinedAndLeftUpdateSortedList(t *testing.T) {
	m := newTestModel("receiver")

	m.handleEvent(snadbox.MemberJoined{Member: snadbox.Member{Name: "zebra"}})
	m.handleEvent(snadbox.MemberJoined{Member: snadbox.Member{Name: "apple"}})

	if len(m.members) != 2 || m.members[0].Name != "apple" || m.members[1].Name != "zebra" {
		t.Fatalf("expected members sorted [apple zebra], got %+v", m.members)
	}

	m.handleEvent(snadbox.MemberLeft{Name: "apple"})
	if len(m.members) != 1 || m.members[0].Name != "zebra" {
		t.Fatalf("expected only zebra to remain, got %+v", m.members)
	}
}

func TestTransferEventsUpdateState(t *testing.T) {
	m := newTestModel("sender")

	m.handleEvent(snadbox.TransferStarted{Peer: "p", File: "f", Size: 100, Direction: snadbox.DirectionSend})
	if len(m.order) != 1 {
		t.Fatalf("expected one in-flight transfer, got %d", len(m.order))
	}
	key := m.order[0]
	if m.transfers[key].failed || m.transfers[key].skipped {
		t.Fatalf("freshly started transfer should be neither failed nor skipped: %+v", m.transfers[key])
	}

	m.handleEvent(snadbox.TransferProgress{Peer: "p", File: "f", Sent: 50, Total: 100, Direction: snadbox.DirectionSend})
	m.handleEvent(snadbox.TransferDone{Peer: "p", File: "f", Direction: snadbox.DirectionSend})
	if m.transfers[key].failed {
		t.Fatal("completed transfer should not be marked failed")
	}

	m.handleEvent(snadbox.TransferSkipped{Peer: "p", File: "g", Direction: snadbox.DirectionSend})
	if len(m.order) != 2 {
		t.Fatalf("expected a second transfer entry for the skipped file, got %d", len(m.order))
	}

	m.handleEvent(snadbox.TransferError{Peer: "p", File: "h", Direction: snadbox.DirectionSend, Err: errors.New("boom")})
	if len(m.order) != 3 {
		t.Fatalf("expected a third transfer entry for the errored file, got %d", len(m.order))
	}
	var errored *transferState
	for _, k := range m.order {
		if k.File == "h" {
			errored = m.transfers[k]
		}
	}
	if errored == nil || !errored.failed || errored.err == nil {
		t.Fatalf("expected file h to be recorded as failed with an error: %+v", errored)
	}
}

func TestReceiverStoppedRendersErrorBanner(t *testing.T) {
	m := newTestModel("receiver")
	m.handleEvent(snadbox.ReceiverStopped{Err: errors.New("listener died")})

	if m.receiverErr == nil {
		t.Fatal("expected receiverErr to be set")
	}
	view := m.View()
	if !strings.Contains(view, "listener died") {
		t.Fatalf("expected View() to surface the receiver error, got:\n%s", view)
	}
}

func TestViewDoesNotPanicAcrossStates(t *testing.T) {
	for _, role := range []string{"sender", "receiver"} {
		m := newTestModel(role)
		_ = m.View() // empty lobby, no transfers

		m.handleEvent(snadbox.MemberJoined{Member: snadbox.Member{Name: "peer"}})
		m.handleEvent(snadbox.TransferSkipped{Peer: "peer", File: "f", Direction: snadbox.DirectionRecv})
		m.handleEvent(snadbox.TransferError{Peer: "peer", File: "g", Direction: snadbox.DirectionRecv, Err: errors.New("x")})

		view := m.View()
		if !strings.Contains(view, "peer") {
			t.Fatalf("expected View() to mention the discovered peer, got:\n%s", view)
		}

		m.quitting = true
		if m.View() != "" {
			t.Fatal("expected View() to render empty once quitting")
		}
	}
}
