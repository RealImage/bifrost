package bfcli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleHeader = lipgloss.NewStyle().
			Bold(true)
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

	output strings.Builder
)

func (m model) View() string {
	output.Reset()
	output.WriteString(styleHeader.Render("Bifrost - Manage CAs"))
	if m.err != nil {
		output.WriteString(styleError.Render("\n\nError: "))
		output.WriteString(m.err.Error())
		output.WriteString(styleError.Render(fmt.Sprintf("Error: %v\n", m.err)))
		return output.String()
	}
	if m.flash != nil {
		output.WriteString("\n")
		output.WriteString(styleFlash.Render(m.flash.msg))
		output.WriteString("\n\n")
		if m.flash.loading {
			return output.String()
		}
	}
	if m.cursor == 0 {
		output.WriteString("> ")
	}
	output.WriteString("New CA")
	output.WriteString(m.newCALabel.View())
	for i, ca := range m.cas {
		if m.cursor == i+1 {
			output.WriteString("> ")
		}
		output.WriteString("(")
		output.WriteString(strconv.FormatInt(int64(i+1), 10))
		output.WriteString(") ")
		output.WriteString(ca.Label)
	}

	if m.cursor > 0 {
		output.WriteString("Start [b]ouncer\nStart [i]ssuer\n[ENTER] start both\n[ESC] or [q]uit to exit\n")
	}
	return output.String()
}
