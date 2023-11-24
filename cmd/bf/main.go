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
