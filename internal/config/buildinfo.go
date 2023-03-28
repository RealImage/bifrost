package config

import (
	"runtime/debug"
)

// GetBuildInfo returns build info from the binary.
func GetBuildInfo() (sha, timestamp string) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, b := range bi.Settings {
		switch b.Key {
		case "vcs.revision":
			sha = b.Value
		case "vcs.time":
			timestamp = b.Value
		}
		if sha != "" && timestamp != "" {
			break
		}
	}
	return
}
