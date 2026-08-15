package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"snad/snadbox"
	"snad/tui"
)

func main() {
	files := os.Args[1:]

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "snad: determine working directory:", err)
		os.Exit(1)
	}

	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			fmt.Fprintf(os.Stderr, "snad: %s: %v\n", f, err)
			os.Exit(1)
		}
	}

	events := make(chan interface{}, 64)

	box, err := snadbox.Join(events)
	if err != nil {
		fmt.Fprintln(os.Stderr, "snad: join snadbox:", err)
		os.Exit(1)
	}
	defer box.Leave()

	ln, port, err := snadbox.Listen(box.Identity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "snad: listen:", err)
		os.Exit(1)
	}
	defer ln.Close()
	box.SetPort(port)

	go snadbox.Serve(ln, cwd, events)

	sender, err := snadbox.NewSender(cwd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "snad: sender setup:", err)
		os.Exit(1)
	}

	model := tui.New(box.Identity, files, sender, events)

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "snad:", err)
		os.Exit(1)
	}
}
