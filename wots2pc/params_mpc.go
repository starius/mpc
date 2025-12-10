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

var (
	garblerInputBitCount int
	evaluatorBitCount    int
	publicBitCount       int
	garblerSecretBits    int

	garbledTableLabelCount int
	outputHintCount        int
	totalWires             int
)

func init() {
	// Validate circuit shapes.
	if wotsChainCircuit.NumParties() != 2 {
		panic(fmt.Sprintf("wots_chain circuit must be 2-party, got %d", wotsChainCircuit.NumParties()))
	}
	if len(wotsChainCircuit.Inputs) != 2 {
		panic(fmt.Sprintf("unexpected input sets: %d", len(wotsChainCircuit.Inputs)))
	}
	garblerInputBitCount = int(wotsChainCircuit.Inputs[0].Type.Bits)
	evaluatorBitCount = int(wotsChainCircuit.Inputs[1].Type.Bits)

	// Garbler input is SkSeed(256) || PubSeed(256) || Addr(256).
	if garblerInputBitCount != 768 {
		panic(fmt.Sprintf("garbler input bits mismatch: %d", garblerInputBitCount))
	}
	if evaluatorBitCount != 256 {
		panic(fmt.Sprintf("evaluator input bits mismatch: %d", evaluatorBitCount))
	}
	garblerSecretBits = 256
	publicBitCount = garblerInputBitCount - garblerSecretBits

	outputHintCount = wotsChainCircuit.Outputs.Size()
	if outputHintCount != 256 {
		panic(fmt.Sprintf("output hint bits mismatch: %d", outputHintCount))
	}
	totalWires = int(wotsChainCircuit.NumWires)

	var labels int
	for _, gate := range wotsChainCircuit.Gates {
		count, err := gateCiphertextCount(gate.Op)
		if err != nil {
			panic(err)
		}
		labels += count
	}
	garbledTableLabelCount = labels
}

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
