// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"os"

	"github.com/RealImage/bifrost/internal/bfcli"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	p := tea.NewProgram(bfcli.New())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Whoops: %v", err)
		os.Exit(1)
	}
}
