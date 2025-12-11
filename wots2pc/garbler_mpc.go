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

// GarblerRound1 sets up the OT sender side and advertises public data/meta.
func GarblerRound1(rng io.Reader, curve elliptic.Curve, public PublicData, meta CircuitMeta) (Round1Payload, *GarblerSession, error) {
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
		Public:    public,
		Meta:      meta,
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
func GarblerRound3(rng io.Reader, curve elliptic.Curve, circ *circuit.Circuit, public PublicData, meta CircuitMeta, state *GarblerSession, skSeedG [32]byte, msg Round2Payload) (Round3Payload, error) {
	if rng == nil {
		return Round3Payload{}, errNilRandomSource
	}
	if state == nil || state.SenderSetup.Scalar == nil {
		return Round3Payload{}, errors.New("wots2pc: invalid garbler session")
	}
	if curve == nil {
		return Round3Payload{}, errNilCurve
	}
	if circ == nil {
		return Round3Payload{}, fmt.Errorf("nil circuit")
	}
	if msg.SessionID != state.SessionID {
		return Round3Payload{}, fmt.Errorf("session id mismatch: got %d want %d", msg.SessionID, state.SessionID)
	}
	if msg.Public != public {
		return Round3Payload{}, fmt.Errorf("public data mismatch")
	}
	if msg.Meta != meta {
		return Round3Payload{}, fmt.Errorf("circuit meta mismatch")
	}

	info, err := deriveInfo(circ)
	if err != nil {
		return Round3Payload{}, err
	}

	const secretBits = 256
	if info.GarblerBits < secretBits {
		return Round3Payload{}, fmt.Errorf("garbler bits %d too small", info.GarblerBits)
	}
	publicBits := info.GarblerBits - secretBits

	var key [32]byte
	if _, err := io.ReadFull(rng, key[:]); err != nil {
		return Round3Payload{}, fmt.Errorf("failed to read garbling key: %w", err)
	}
	garbled, err := circ.Garble(rng, key[:])
	if err != nil {
		return Round3Payload{}, err
	}

	secretBitsArr := bytesToBitsLittle(skSeedG[:])
	if len(secretBitsArr) != secretBits {
		return Round3Payload{}, fmt.Errorf("garbler secret mismatch: got %d bits want %d", len(secretBitsArr), secretBits)
	}
	garblerLabels := make([]ot.Label, secretBits)
	for i := 0; i < secretBits; i++ {
		garblerLabels[i] = circuit.LabelForBit(garbled.Wires[i], secretBitsArr[i])
	}

	publicLabels := make([]ot.Wire, publicBits)
	startPublic := secretBits
	for i := 0; i < publicBits; i++ {
		publicLabels[i] = garbled.Wires[startPublic+i]
	}

	evaluatorWires := garbled.Wires[info.GarblerBits : info.GarblerBits+info.EvaluatorBits]
	ciphertexts, err := ot.EncryptCOCiphertexts(curve, state.SenderSetup, msg.Choices, evaluatorWires)
	if err != nil {
		return Round3Payload{}, err
	}

	outputHints := make([]ot.Wire, info.OutputBits)
	start := int(circ.NumWires) - info.OutputBits
	copy(outputHints, garbled.Wires[start:])

	return Round3Payload{
		SessionID:     state.SessionID,
		Ciphertexts:   ciphertexts,
		Key:           key,
		GarbledTables: garbled.Gates,
		GarblerInputs: garblerLabels,
		PublicInputs:  publicLabels,
		OutputHints:   outputHints,
		Public:        public,
		Meta:          meta,
	}, nil
}
