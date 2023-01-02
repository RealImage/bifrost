package config

import (
	"runtime/debug"
	"time"
)

func GetBuildInfo() (sha string, timestamp time.Time, ok bool) {
	var bi *debug.BuildInfo
	bi, ok = debug.ReadBuildInfo()
	for _, b := range bi.Settings {
		switch b.Key {
		case "vcs.revision":
			sha = b.Value
		case "vcs.time":
			if ts, err := time.Parse(time.RFC3339, b.Value); err == nil {
				timestamp = ts
			}
		}
	}
	return
}
