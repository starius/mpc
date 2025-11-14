package sha2pc

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
)

// Config specifies how protocol sessions are created.
type Config struct {
	// Rand feeds protocol randomness. Defaults to crypto/rand.Reader.
	Rand io.Reader
	// Curve selects the OT group. Defaults to P-256.
	Curve elliptic.Curve
}

// rand selects the session RNG, defaulting to crypto/rand.Reader.
func (cfg *Config) rand() io.Reader {
	if cfg != nil && cfg.Rand != nil {
		return cfg.Rand
	}
	return rand.Reader
}

// curve selects the OT curve, defaulting to P-256.
func (cfg *Config) curve() elliptic.Curve {
	if cfg != nil && cfg.Curve != nil {
		return cfg.Curve
	}
	return elliptic.P256()
}
