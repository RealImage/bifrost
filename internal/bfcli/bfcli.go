package bfcli

import (
	tea "github.com/charmbracelet/bubbletea"
)

func New() tea.Model {
	return model{
		cas:    []cadata{},
		runIdx: -1,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(func() tea.Msg { return "Loading CAs..." }, m.loadCAs)
}
