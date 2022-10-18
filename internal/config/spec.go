package config

import "github.com/google/uuid"

const Prefix = "BF"

// Spec configures a bifrost server
type Spec struct {
	Host        string    `default:"127.0.0.1"`
	CrtUri      string    `envconfig:"CRT_URI" default:"crt.pem"`
	KeyUri      string    `envconfig:"KEY_URI" default:"key.pem"`
	IDNamespace uuid.UUID `envconfig:"BFID_NAMESPACE"`
}
