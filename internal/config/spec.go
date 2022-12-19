package config

import (
	"time"

	"github.com/google/uuid"
)

const Prefix = "BF"

// Spec configures a bifrost server
type Spec struct {
	Host                string        `default:"127.0.0.1"`
	CrtUri              string        `envconfig:"CRT_URI" default:"crt.pem"`
	KeyUri              string        `envconfig:"KEY_URI" default:"key.pem"`
	Namespace           uuid.UUID     `envconfig:"NAMESPACE"`
	MetricsPushUrl      string        `envconfig:"METRICS_PUSH_URL"`
	MetricsPushInterval time.Duration `envconfig:"METRICS_PUSH_INTERVAL"`
}
