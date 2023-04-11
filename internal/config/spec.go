package config

import (
	"github.com/google/uuid"
)

const Prefix = "BF"

// Spec configures a bifrost server.
type Spec struct {
	Address   string    `envconfig:"ADDR" default:"127.0.0.1:8080"`
	CrtUri    string    `envconfig:"CRT"  default:"crt.pem"`
	KeyUri    string    `envconfig:"KEY"  default:"key.pem"`
	Namespace uuid.UUID `envconfig:"NS"   default:"1512daa4-ddc1-41d1-8673-3fd19d2f338d"`
}
