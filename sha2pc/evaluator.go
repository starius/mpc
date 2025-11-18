package sha2pc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

// EvaluatorSession captures the immutable evaluator-side context between rounds.
// It is produced by EvaluatorRound2, consumed in EvaluatorRound4, and can be
// persisted and restored without additional mutation.
type EvaluatorSession struct {
	key          [32]byte
	garbled      [][]ot.Label
	outputHints  []ot.Wire
	wires        []ot.Label
	choiceBundle ot.COChoiceBundle
}

// EvaluatorRound2 ingests the Round1 payload and evaluator input,
// returning the Round2 payload and updated state.
// EvaluatorRound2 requires a non-nil randomness source and curve.
func EvaluatorRound2(rng io.Reader, curve elliptic.Curve, msg Round1Payload, preimagePart [sha256.Size]byte) (Round2Payload, *EvaluatorSession, error) {
	if rng == nil {
		return Round2Payload{}, nil, errNilRandomSource
	}
	if curve == nil {
		return Round2Payload{}, nil, errNilCurve
	}
	circ := sha256xorCircuit
	if circ.NumParties() != 2 {
		return Round2Payload{}, nil, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}
	state := &EvaluatorSession{}
	if msg.OT.CurveName != curve.Params().Name {
		return Round2Payload{}, nil, fmt.Errorf("curve mismatch: %s vs %s",
			msg.OT.CurveName, curve.Params().Name)
	}
	state.key = msg.Key
	state.garbled = msg.GarbledTables
	state.outputHints = msg.OutputHints
	state.wires = make([]ot.Label, circ.NumWires)
	copy(state.wires[:hashInputBitCount], msg.GarblerInputs)

	bits := bytesToBitsLittle(preimagePart[:])
	if len(bits) != hashInputBitCount {
		return Round2Payload{}, nil, fmt.Errorf("evaluator input mismatch: got %d bits want %d",
			len(bits), hashInputBitCount)
	}

	bundle, choices, err := ot.BuildCOChoices(rng, curve, msg.OT.A.X, msg.OT.A.Y, bits)
	if err != nil {
		return Round2Payload{}, nil, err
	}
	state.choiceBundle = bundle

	return Round2Payload{Choices: choices}, state, nil
}

// EvaluatorRound4 processes Round3 payload, returns the hash and Round4 payload.
// The curve argument must be non-nil.
func EvaluatorRound4(curve elliptic.Curve, state *EvaluatorSession, msg Round3Payload) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if state == nil || len(state.choiceBundle.Scalars) == 0 {
		return digest, fmt.Errorf("invalid evaluator state for round 4")
	}
	if curve == nil {
		return digest, errNilCurve
	}
	labels, err := ot.DecryptCOCiphertexts(curve, state.choiceBundle, msg.Ciphertexts)
	if err != nil {
		return digest, err
	}
	wires := make([]ot.Label, len(state.wires))
	copy(wires, state.wires)
	copy(wires[hashInputBitCount:], labels)

	if err := sha256xorCircuit.Eval(state.key[:], wires, state.garbled); err != nil {
		return digest, err
	}

	if len(state.outputHints) != sha256xorCircuit.Outputs.Size() {
		return digest, fmt.Errorf("output hint mismatch: have %d want %d",
			len(state.outputHints), sha256xorCircuit.Outputs.Size())
	}

	start := sha256xorCircuit.NumWires - len(state.outputHints)
	outputBits, err := circuit.BitsFromLabels(state.outputHints, wires[start:])
	if err != nil {
		return digest, err
	}

	bytes := bitsToBytesLittle(outputBits)
	if len(bytes) != sha256.Size {
		return digest,
			fmt.Errorf("unexpected output length %d", len(bytes))
	}

	copy(digest[:], bytes)

	return digest, nil
}
