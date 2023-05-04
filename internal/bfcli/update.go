package bfcli

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/charm/fs"
)

type model struct {
	err     error
	flash   *flash
	fs      *fs.FS
	cas     []cadata
	cursor  int
	runIdx  int
	caLabel textinput.Model
}

type flash struct {
	msg     string
	ttl     time.Time
	loading bool
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.flash != nil {
		if time.Now().After(m.flash.ttl) {
			m.flash = nil
		}
	}
	switch msg := msg.(type) {
	case error:
		m.err = msg
		return m, tea.Quit
	case flash:
		m.flash = &msg
	case string:
		m.flash = &flash{
			msg: msg,
			ttl: time.Now().Add(10 * time.Second),
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			if len(m.cas) == 0 {
				break
			}
			if m.cursor > 0 {
				m.cursor--
			} else {
				m.cursor = len(m.cas) - 1
			}
		case "down", "j":
			if len(m.cas) == 0 {
				break
			}
			if m.cursor < len(m.cas)-1 {
				m.cursor++
			} else {
				m.cursor = 0
			}
		case "enter", " ":
			if m.cursor == 0 {
				return m, m.newCA
			}
			return m, tea.Batch(m.startIssuer, m.startBouncer)
		case "i":
			return m, m.startIssuer
		case "b":
			return m, m.startBouncer
		}
	case []cadata:
		m.cas = msg
	}
	var cmd tea.Cmd
	m.caLabel, cmd = m.caLabel.Update(msg)
	return m, cmd
}
