package sha2pc

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/internal/sha256xor"
)

// Config specifies how protocol sessions are created.
type Config struct {
	// CircuitLoader provides the SHA256(XOR) circuit. Defaults to the
	// embedded generator output.
	CircuitLoader func() (*circuit.Circuit, error)
	// Rand feeds protocol randomness. Defaults to crypto/rand.Reader.
	Rand io.Reader
	// Curve selects the OT group. Defaults to P-256.
	Curve elliptic.Curve
}

func (cfg *Config) loader() func() (*circuit.Circuit, error) {
	if cfg != nil && cfg.CircuitLoader != nil {
		return cfg.CircuitLoader
	}
	return sha256xor.LoadCircuit
}

func (cfg *Config) rand() io.Reader {
	if cfg != nil && cfg.Rand != nil {
		return cfg.Rand
	}
	return rand.Reader
}

func (cfg *Config) curve() elliptic.Curve {
	if cfg != nil && cfg.Curve != nil {
		return cfg.Curve
	}
	return elliptic.P256()
}
