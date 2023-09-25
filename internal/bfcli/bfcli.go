// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	return tea.Batch(
		func() tea.Msg { return flash{msg: "Loading CAs...", loading: true} },
		m.loadCAs,
	)
}
