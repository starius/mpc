package wots2pc

import (
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

var (
	errNilRandomSource = errors.New("wots2pc: randomness source must not be nil")
	errNilCurve        = errors.New("wots2pc: elliptic curve must not be nil")
)

// GarblerRound1 sets up the OT sender side.
func GarblerRound1(rng io.Reader, curve elliptic.Curve) (Round1Payload, *GarblerSession, error) {
	if rng == nil {
		return Round1Payload{}, nil, errNilRandomSource
	}
	if curve == nil {
		return Round1Payload{}, nil, errNilCurve
	}
	setup, err := ot.GenerateCOSenderSetup(rng, curve)
	if err != nil {
		return Round1Payload{}, nil, err
	}
	var sidBuf [8]byte
	if _, err := io.ReadFull(rng, sidBuf[:]); err != nil {
		return Round1Payload{}, nil, fmt.Errorf("failed to read session id: %w", err)
	}
	sessionID := binary.BigEndian.Uint64(sidBuf[:])
	state := &GarblerSession{
		SessionID:   sessionID,
		SenderSetup: setup,
	}
	payload := Round1Payload{
		SessionID: sessionID,
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

// GarblerRound3 garbles the chain circuit and packages payloads for evaluator.
// pubSeed and addr are public; they are modeled as garbler inputs so we can
// supply both labels to the evaluator for reuse across addresses.
func GarblerRound3(rng io.Reader, curve elliptic.Curve, state *GarblerSession, skSeedG [32]byte, msg Round2Payload) (Round3Payload, error) {
	if rng == nil {
		return Round3Payload{}, errNilRandomSource
	}
	if state == nil || state.SenderSetup.Scalar == nil {
		return Round3Payload{}, errors.New("wots2pc: invalid garbler session")
	}
	if curve == nil {
		return Round3Payload{}, errNilCurve
	}
	circ := wotsChainCircuit
	if circ.NumParties() != 2 {
		return Round3Payload{}, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}
	if msg.SessionID != state.SessionID {
		return Round3Payload{}, fmt.Errorf("session id mismatch: got %d want %d", msg.SessionID, state.SessionID)
	}

	var key [32]byte
	if _, err := io.ReadFull(rng, key[:]); err != nil {
		return Round3Payload{}, fmt.Errorf("failed to read garbling key: %w", err)
	}
	garbled, err := circ.Garble(rng, key[:])
	if err != nil {
		return Round3Payload{}, err
	}

	// Garbler secret labels (skSeedG).
	gBits := garblerSecretBits
	gBitsAll := garblerInputBitCount
	secretBits := bytesToBitsLittle(skSeedG[:])
	if len(secretBits) != gBits {
		return Round3Payload{}, fmt.Errorf("garbler input mismatch: got %d bits want %d", len(secretBits), gBits)
	}
	garblerLabels := make([]ot.Label, gBits)
	for i := 0; i < gBits; i++ {
		garblerLabels[i] = circuit.LabelForBit(garbled.Wires[i], secretBits[i])
	}

	// Public wires (PubSeed||Addr).
	publicLabels := make([]ot.Wire, publicBitCount)
	startPublic := gBits
	for i := 0; i < publicBitCount; i++ {
		publicLabels[i] = garbled.Wires[startPublic+i]
	}

	// Evaluator wires.
	evaluatorWires := garbled.Wires[gBitsAll : gBitsAll+evaluatorBitCount]
	ciphertexts, err := ot.EncryptCOCiphertexts(curve, state.SenderSetup, msg.Choices, evaluatorWires)
	if err != nil {
		return Round3Payload{}, err
	}

	// Output hints.
	outputs := circ.Outputs.Size()
	outputHints := make([]ot.Wire, outputs)
	start := int(circ.NumWires) - outputs
	copy(outputHints, garbled.Wires[start:])

	return Round3Payload{
		SessionID:     state.SessionID,
		Ciphertexts:   ciphertexts,
		Key:           key,
		GarbledTables: garbled.Gates,
		GarblerInputs: garblerLabels,
		PublicInputs:  publicLabels,
		OutputHints:   outputHints,
	}, nil
}
