package tinyca

import (
	"errors"
	"strings"
	"time"
)

// ParseValidity parses the notBefore and notAfter strings into time.Time values.
// The notBefore and notAfter strings can be in RFC3339 format, or a duration
// from the current time.
// Durations are prefixed with either '+' or '-'.
// If notBefore is empty, it defaults to the current time.
// If notAfter is empty, it defaults to one hour from the current time.
// If notBefore is "now", it is set to the current time.
// The minimum validity period is one minute.
func ParseValidity(nb string, na string) (time.Time, time.Time, error) {
	now := time.Now()
	notBefore := now
	if nb != "" && nb != "now" {
		var err error
		if notBefore, err = parseTimeOrOffset(nb); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	notAfter := notBefore.Add(time.Hour)
	if na != "" {
		var err error
		if notAfter, err = parseTimeOrOffset(na); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}

	if notBefore.After(notAfter) {
		return time.Time{}, time.Time{}, errors.New("negative validity period")
	}

	if notAfter.Sub(notBefore) < time.Minute {
		return time.Time{}, time.Time{}, errors.New("validity period is too short")
	}

	return notBefore, notAfter, nil
}

func parseTimeOrOffset(t string) (time.Time, error) {
	if strings.HasPrefix(t, "+") {
		d, err := time.ParseDuration(t[1:])
		if err != nil {
			return time.Time{}, err
		}
		return time.Now().Add(d), nil
	}
	return time.Parse(time.RFC3339, t)
}
