package sha2pc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

// Garbler drives the garbling side (party A) of the protocol.
type Garbler struct {
	// rand yields randomness for garbling and OT.
	rand io.Reader
	// circ stores the shared computation circuit.
	circ *circuit.Circuit
	// curve selects the OT elliptic curve.
	curve elliptic.Curve
	// garblerBits counts the garbler's private input bits.
	garblerBits int
	// evaluatorBits counts the evaluator's private input bits.
	evaluatorBits int

	// garbled caches the latest garbled circuit.
	garbled *circuit.Garbled
	// key stores the AES garbling key.
	key [32]byte
	// otState keeps the pending OT sender state.
	otState *otSenderState
	// completed tracks whether Finalize was invoked.
	completed bool
}

// NewGarbler constructs a garbler session with the provided config.
func NewGarbler(cfg *Config) (*Garbler, error) {
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

	return &Garbler{
		rand:          cfg.rand(),
		circ:          circ,
		curve:         cfg.curve(),
		garblerBits:   gBits,
		evaluatorBits: eBits,
	}, nil
}

// Round1 garbles the circuit with the provided input and returns the
// first protocol message which must be sent to the evaluator.
func (g *Garbler) Round1(input [32]byte) (Message, error) {
	if _, err := io.ReadFull(g.rand, g.key[:]); err != nil {
		return nil, fmt.Errorf("failed to read key randomness: %w", err)
	}

	garbled, err := g.circ.Garble(g.key[:])
	if err != nil {
		return nil, err
	}
	g.garbled = garbled

	bits := bytesToBitsLittle(input[:])
	if len(bits) != g.garblerBits {
		return nil, fmt.Errorf("garbler input mismatch: got %d bits want %d",
			len(bits), g.garblerBits)
	}
	garblerLabels := make([]ot.Label, g.garblerBits)
	for i := 0; i < g.garblerBits; i++ {
		wire := garbled.Wires[i]
		if bits[i] {
			garblerLabels[i] = wire.L1
		} else {
			garblerLabels[i] = wire.L0
		}
	}

	evaluatorWires := garbled.Wires[g.garblerBits : g.garblerBits+g.evaluatorBits]
	otState, err := newOTSenderState(g.curve, evaluatorWires)
	if err != nil {
		return nil, err
	}
	g.otState = otState

	var payload chunkWriter
	payload.Write(g.key[:])
	payload.writeChunk(encodeGarbledTables(garbled.Gates))
	payload.writeChunk(encodeLabels(garblerLabels))
	payload.writeChunk(encodeOutputHints(selectOutputWires(g.circ, garbled)))
	payload.writeChunk(encodeOTSetup(g.curve, otState.Ax, otState.Ay))

	g.completed = false
	return newMessage(round1Kind, payload.Bytes()), nil
}

// Round3 consumes the evaluator's OT request (Round2) and returns the
// encrypted label payload that must be forwarded back to the
// evaluator.
func (g *Garbler) Round3(msg Message) (Message, error) {
	payload, err := parseMessage(msg, round2Kind)
	if err != nil {
		return nil, err
	}
	reader := newChunkReader(payload)
	pointsData, err := reader.readChunk()
	if err != nil {
		return nil, err
	}
	points, err := decodePoints(pointsData)
	if err != nil {
		return nil, err
	}
	ciphertext, err := g.otState.encrypt(points)
	if err != nil {
		return nil, err
	}
	var out chunkWriter
	out.writeChunk(ciphertext)
	return newMessage(round3Kind, out.Bytes()), nil
}

// Finalize verifies the evaluator's final share (Round4) and returns
// the agreed SHA256 hash.
func (g *Garbler) Finalize(msg Message) ([32]byte, error) {
	var hash [32]byte
	payload, err := parseMessage(msg, round4Kind)
	if err != nil {
		return hash, err
	}
	if len(payload) != sha256.Size {
		return hash, fmt.Errorf("invalid result length %d", len(payload))
	}
	copy(hash[:], payload[:sha256.Size])
	g.completed = true
	return hash, nil
}
