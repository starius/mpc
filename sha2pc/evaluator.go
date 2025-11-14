package sha2pc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

// Evaluator drives the evaluator side (party B) of the protocol.
type Evaluator struct {
	// rand yields randomness for OT choices.
	rand io.Reader

	// circ stores the shared computation circuit.
	circ *circuit.Circuit

	// curve selects the OT elliptic curve.
	curve elliptic.Curve

	// garblerBits counts the garbler's input bits.
	garblerBits int

	// evaluatorBits counts the evaluator's input bits.
	evaluatorBits int

	// key stores the AES garbling key.
	key [32]byte

	// garbled caches the received gate tables.
	garbled [][]ot.Label

	// wires holds the evaluator's running wire labels.
	wires []ot.Label

	// outputHints stores the garbler's output label pairs.
	outputHints []ot.Wire

	// receiver keeps the active OT receiver state.
	receiver *otReceiverState
}

// NewEvaluator constructs an evaluator session with the provided config.
func NewEvaluator(cfg *Config) (*Evaluator, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	circ, err := loadSHA256XORCircuit()
	if err != nil {
		return nil, err
	}
	if circ.NumParties() != 2 {
		return nil, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}
	gBits := int(circ.Inputs[0].Type.Bits)
	eBits := int(circ.Inputs[1].Type.Bits)

	return &Evaluator{
		rand:          cfg.rand(),
		circ:          circ,
		curve:         cfg.curve(),
		garblerBits:   gBits,
		evaluatorBits: eBits,
	}, nil
}

// Round2 ingests the garbler's Round1 message and the evaluator's
// input, prepares the OT queries, and returns Round2 which must be
// forwarded to the garbler.
func (e *Evaluator) Round2(msg Message, input [32]byte) (Message, error) {
	payload, err := parseMessage(msg, round1Kind)
	if err != nil {
		return nil, err
	}
	reader := newChunkReader(payload)

	if _, err := io.ReadFull(reader, e.key[:]); err != nil {
		return nil, err
	}
	garbledData, err := reader.readChunk()
	if err != nil {
		return nil, err
	}
	tables, err := decodeGarbledTables(garbledData)
	if err != nil {
		return nil, err
	}
	garblerInputData, err := reader.readChunk()
	if err != nil {
		return nil, err
	}
	garblerLabels, err := decodeLabels(garblerInputData)
	if err != nil {
		return nil, err
	}
	outputHintData, err := reader.readChunk()
	if err != nil {
		return nil, err
	}
	outputHints, err := decodeOutputHints(outputHintData)
	if err != nil {
		return nil, err
	}
	otSetup, err := reader.readChunk()
	if err != nil {
		return nil, err
	}
	curveName, Ax, Ay, err := decodeOTSetup(otSetup)
	if err != nil {
		return nil, err
	}
	if curveName != e.curve.Params().Name {
		return nil, fmt.Errorf("curve mismatch: %s vs %s",
			curveName, e.curve.Params().Name)
	}

	e.garbled = tables
	e.outputHints = outputHints
	e.wires = make([]ot.Label, e.circ.NumWires)
	copy(e.wires[:e.garblerBits], garblerLabels)

	bits := bytesToBitsLittle(input[:])
	if len(bits) != e.evaluatorBits {
		return nil, fmt.Errorf("evaluator input mismatch: got %d bits want %d",
			len(bits), e.evaluatorBits)
	}

	receiver := newOTReceiverState(e.curve, Ax, Ay, e.evaluatorBits)
	points := make([]ecPoint, e.evaluatorBits)
	for i := 0; i < e.evaluatorBits; i++ {
		point, err := receiver.buildChoice(i, bits[i])
		if err != nil {
			return nil, err
		}
		points[i] = point
	}
	e.receiver = receiver

	var out chunkWriter
	out.writeChunk(encodePoints(points))
	return newMessage(round2Kind, out.Bytes()), nil
}

// Round4 processes the garbler's Round3 response, evaluates the
// circuit, and returns the resulting hash alongside the Round4
// payload that can optionally be sent back to the garbler so that both
// parties learn the digest.
func (e *Evaluator) Round4(msg Message) ([sha256.Size]byte, Message, error) {
	var digest [sha256.Size]byte
	payload, err := parseMessage(msg, round3Kind)
	if err != nil {
		return digest, nil, err
	}
	reader := newChunkReader(payload)
	cipherData, err := reader.readChunk()
	if err != nil {
		return digest, nil, err
	}
	labels, err := e.receiver.decrypt(cipherData)
	if err != nil {
		return digest, nil, err
	}
	copy(e.wires[e.garblerBits:], labels)

	err = e.circ.Eval(e.key[:], e.wires, e.garbled)
	if err != nil {
		return digest, nil, err
	}

	if len(e.outputHints) != e.circ.Outputs.Size() {
		return digest, nil, fmt.Errorf("output hint mismatch: have %d want %d",
			len(e.outputHints), e.circ.Outputs.Size())
	}

	outputBits := make([]bool, len(e.outputHints))
	start := e.circ.NumWires - len(e.outputHints)
	for i := 0; i < len(e.outputHints); i++ {
		label := e.wires[start+i]
		hint := e.outputHints[i]
		switch {
		case label.Equal(hint.L0):
			outputBits[i] = false
		case label.Equal(hint.L1):
			outputBits[i] = true
		default:
			return digest, nil,
				fmt.Errorf("output label mismatch at %d: %s vs %s/%s",
					i, label, hint.L0, hint.L1)
		}
	}

	bytes := bitsToBytesLittle(outputBits)
	if len(bytes) != sha256.Size {
		return digest, nil,
			fmt.Errorf("unexpected output length %d", len(bytes))
	}
	copy(digest[:], bytes)

	return digest, newMessage(round4Kind, digest[:]), nil
}
