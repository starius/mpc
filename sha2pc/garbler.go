package sha2pc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/ot"
)

// errNilRandomSource indicates that a required randomness source was nil.
var errNilRandomSource = errors.New("sha2pc: randomness source must not be nil")

// errNilCurve indicates that a required elliptic curve was nil.
var errNilCurve = errors.New("sha2pc: elliptic curve must not be nil")

// GarblerSession captures the immutable garbler-side context between rounds.
// It is produced by GarblerRound1, consumed in GarblerRound3, and can be
// persisted and restored without additional mutation.
type GarblerSession struct {
	key         [32]byte
	senderSetup ot.COSenderSetup
	wires       []ot.Wire
}

// GarblerRound1 garbles the circuit for the provided input and returns the
// Round1 payload together with the state needed for later rounds. Both rng and
// curve must be non-nil.
// GarblerRound1 requires a non-nil randomness source and curve.
func GarblerRound1(rng io.Reader, curve elliptic.Curve, preimagePart [sha256.Size]byte) (Round1Payload, *GarblerSession, error) {
	if rng == nil {
		return Round1Payload{}, nil, errNilRandomSource
	}
	if curve == nil {
		return Round1Payload{}, nil, errNilCurve
	}

	circ := sha256xorCircuit
	if circ.NumParties() != 2 {
		return Round1Payload{}, nil, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}
	gBits := hashInputBitCount
	eBits := hashInputBitCount

	state := &GarblerSession{}

	if _, err := io.ReadFull(rng, state.key[:]); err != nil {
		return Round1Payload{}, nil, fmt.Errorf("failed to read key randomness: %w", err)
	}

	garbled, err := circ.Garble(rng, state.key[:])
	if err != nil {
		return Round1Payload{}, nil, err
	}

	bits := bytesToBitsLittle(preimagePart[:])
	if len(bits) != gBits {
		return Round1Payload{}, nil, fmt.Errorf("garbler input mismatch: got %d bits want %d",
			len(bits), gBits)
	}
	garblerLabels := make([]ot.Label, gBits)
	for i := 0; i < gBits; i++ {
		wire := garbled.Wires[i]
		if bits[i] {
			garblerLabels[i] = wire.L1
		} else {
			garblerLabels[i] = wire.L0
		}
	}

	evaluatorWires := garbled.Wires[gBits : gBits+eBits]
	setup, err := ot.GenerateCOSenderSetup(rng, curve)
	if err != nil {
		return Round1Payload{}, nil, err
	}
	state.senderSetup = setup

	// Copy evaluator wires, so we can drop the garbled circuit from state.
	state.wires = make([]ot.Wire, len(evaluatorWires))
	copy(state.wires, evaluatorWires)

	// Choose the wires that correspond to circuit outputs.
	outputs := circ.Outputs.Size()
	outputHints := make([]ot.Wire, outputs)
	start := int(circ.NumWires) - outputs
	copy(outputHints, garbled.Wires[start:])

	payload := Round1Payload{
		Key:           state.key,
		GarbledTables: garbled.Gates,
		GarblerInputs: garblerLabels,
		OutputHints:   outputHints,
		OT: OTSenderSetup{
			CurveName: setup.CurveName,
			A: ot.ECPoint{
				X: new(big.Int).Set(setup.Ax),
				Y: new(big.Int).Set(setup.Ay),
			},
		},
	}

	return payload, state, nil
}

// GarblerRound3 processes the evaluator's OT choices and emits Round3 payload.
// The curve argument must be non-nil.
func GarblerRound3(state *GarblerSession, curve elliptic.Curve, req Round2Payload) (Round3Payload, error) {
	if state == nil || state.senderSetup.Scalar == nil {
		return Round3Payload{}, errors.New("sha2pc: invalid garbler session")
	}
	if curve == nil {
		return Round3Payload{}, errNilCurve
	}
	ciphertexts, err := ot.EncryptCOCiphertexts(curve, state.senderSetup, req.Choices, state.wires)
	if err != nil {
		return Round3Payload{}, err
	}

	return Round3Payload{Ciphertexts: ciphertexts}, nil
}
