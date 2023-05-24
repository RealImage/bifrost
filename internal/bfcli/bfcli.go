package bfcli

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func New() tea.Model {
	return model{
		cas:        []cadata{},
		runIdx:     -1,
		newCALabel: textinput.New(),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(func() tea.Msg { return flash{msg: "Loading CAs...", loading: true} }, m.loadCAs)
}
