package bfcli

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Border(lipgloss.ThickBorder(), true, false).
			BorderForeground(lipgloss.Color("63"))
	styleError = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#000000"))
	styleFlash = lipgloss.NewStyle().
			Faint(true).
			Blink(true).
			Foreground(lipgloss.CompleteAdaptiveColor{
			Light: lipgloss.CompleteColor{TrueColor: "#d7ffae", ANSI256: "193", ANSI: "11"},
			Dark:  lipgloss.CompleteColor{TrueColor: "#d75fee", ANSI256: "163", ANSI: "5"},
		})
)

func (m model) View() string {
	s := styleHeader.Render("Bifrost - Manage CAs")
	if m.err != nil {
		s += styleError.Render(fmt.Sprintf("Error: %v\n", m.err))
		return s
	}
	s += "\n"
	if m.flash != nil {
		s += styleFlash.Render(fmt.Sprintf("%s\n", m.flash.msg))
		if m.flash.loading {
			return s
		}
	}
	s += "\n"
	if m.cursor == 0 {
		s += "> "
	}
	s += "Create a new Certificate Authority\n"
	s += m.caLabel.View()
	for i, ca := range m.cas {
		if m.cursor == i+1 {
			s += "> "
		}
		s += fmt.Sprintf("%d) %s\n", i+1, ca.Label)
	}

	if m.cursor > 0 {
		s += "\n"
		s += "Press enter to start issuer and bouncer."
		s += "\n"
		s += "Press i to start issuer, b to start bouncer, or d to delete the domain."

	}
	s += "\n"
	s += "Press q to quit."
	return s
}
