package sha256xor

import (
	"bytes"
	_ "embed"

	"github.com/markkurossi/mpc/circuit"
)

// circuitBlob holds the compiled MPCLC circuit for SHA256(XOR).
//
//go:embed sha256xor.mpclc
var circuitBlob []byte

// LoadCircuit returns the SHA256 XOR circuit parsed from the embedded
// MPCLC blob.
func LoadCircuit() (*circuit.Circuit, error) {
	return circuit.ParseMPCLC(bytes.NewReader(circuitBlob))
}
