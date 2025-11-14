package sha2pc

import (
	"crypto/elliptic"
	"fmt"
)

// CurveP256 is the default curve used for SHA256(XOR) evaluations.
var CurveP256 = elliptic.P256()

// hashInputBitCount locks the 32-byte preimage size (256 bits).
const hashInputBitCount = 32 * 8

// init validates that the circuit matches the expected bit widths.
func init() {
	if bits := int(sha256xorCircuit.Inputs[0].Type.Bits); bits != hashInputBitCount {
		panic(fmt.Sprintf("garbler bit-count mismatch: %d != %d", bits, hashInputBitCount))
	}
	if bits := int(sha256xorCircuit.Inputs[1].Type.Bits); bits != hashInputBitCount {
		panic(fmt.Sprintf("evaluator bit-count mismatch: %d != %d", bits, hashInputBitCount))
	}
}
