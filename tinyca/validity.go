package tinyca

import (
	"errors"
	"strings"
	"time"
)

// MaxIssueValidity is the maximum validity period for issued certificates.
const MaxIssueValidity = 30 * 24 * time.Hour

// ParseValidity parses notBefore and notAfter into time.Time values.
// notBefore and notAfter can either be in RFC3339 format or a duration
// offset from the current time.
// Offset durations are parsed using time.ParseDuration.
// If notBefore is empty or set to "now", it defaults to the current time.
// If notAfter is empty, it behaves as if it is set to "+1h".
// Negative validity periods are not allowed.
func ParseValidity(notBefore string, notAfter string) (time.Time, time.Time, error) {
	now := time.Now()
	nbf := now
	if notBefore != "" && notBefore != "now" {
		var err error
		if nbf, err = parseTimeOrOffset(notBefore); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}

	naf := nbf.Add(time.Hour)
	if notAfter != "" {
		var err error
		if naf, err = parseTimeOrOffset(notAfter); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}

	if nbf.After(naf) {
		return time.Time{}, time.Time{}, errors.New("negative validity period")
	}

	if naf.Sub(nbf) > MaxIssueValidity {
		return time.Time{}, time.Time{}, errors.New("validity period is too long")
	}

	return nbf, naf, nil
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
