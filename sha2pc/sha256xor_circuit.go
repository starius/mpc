package sha2pc

import (
	"bytes"
	_ "embed"

	"github.com/markkurossi/mpc/circuit"
)

// sha256xorCircuitBlob stores the compiled SHA256(XOR) circuit.
//
//go:embed sha256xor.mpclc
var sha256xorCircuitBlob []byte

// loadSHA256XORCircuit parses the embedded circuit blob into a Circuit.
func loadSHA256XORCircuit() (*circuit.Circuit, error) {
	return circuit.ParseMPCLC(bytes.NewReader(sha256xorCircuitBlob))
}
