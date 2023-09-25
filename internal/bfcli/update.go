// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bfcli

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/charm/fs"
)

type model struct {
	err        error
	flash      *flash
	fs         *fs.FS
	cas        []cadata
	cursor     int
	runIdx     int
	newCALabel textinput.Model
}

type flash struct {
	msg     string
	ttl     time.Time
	loading bool
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
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
				cmds = append(cmds, m.newCA)
			}
			cmds = append(cmds, m.startIssuer, m.startBouncer)
		case "i":
			cmds = append(cmds, m.startIssuer)
		case "b":
			cmds = append(cmds, m.startBouncer)
		}
		if m.cursor == 0 {
			m.newCALabel.Focus()
		} else {
			m.newCALabel.Blur()
		}
	case []cadata:
		m.cas = msg
	}

	var cmd tea.Cmd
	m.newCALabel, cmd = m.newCALabel.Update(msg)
	return m, tea.Batch(append(cmds, cmd)...)
}
