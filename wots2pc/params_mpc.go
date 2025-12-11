package wots2pc

import (
	"crypto/elliptic"
	"fmt"

	"github.com/markkurossi/mpc/circuit"
)

// CurveP256 is the default curve used for WOTS+ evaluations.
var CurveP256 = elliptic.P256()

const (
	labelByteLen     = 16
	garblingKeyBytes = 32
	sessionIDBytes   = 8
)

func gateCiphertextCount(op circuit.Operation) (int, error) {
	switch op {
	case circuit.XOR, circuit.XNOR:
		return 0, nil
	case circuit.AND:
		return 2, nil
	case circuit.OR:
		return 3, nil
	case circuit.INV:
		return 1, nil
	default:
		return 0, fmt.Errorf("wots2pc: unsupported gate operation %v", op)
	}
}
