package config

import (
	"runtime/debug"
)

func GetBuildInfo() (sha, timestamp string, ok bool) {
	var bi *debug.BuildInfo
	bi, ok = debug.ReadBuildInfo()
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
