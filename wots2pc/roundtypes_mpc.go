package wots2pc

import "github.com/markkurossi/mpc/ot"

// Round1Payload carries OT setup from garbler.
type Round1Payload struct {
	SessionID uint64
	OT        OTSenderSetup
}

// OTSenderSetup exposes the sender metadata needed for OT.
type OTSenderSetup struct {
	CurveName string
	A         ot.ECPoint
}

// Round2Payload carries evaluator OT choices.
type Round2Payload struct {
	SessionID uint64
	CurveName string
	Choices   []ot.ECPoint
}

// Round3Payload bundles the garbled circuit and labels.
type Round3Payload struct {
	SessionID     uint64
	Ciphertexts   []ot.LabelCiphertext
	Key           [32]byte
	GarbledTables [][]ot.Label
	GarblerInputs []ot.Label // for skSeedG bits
	PublicInputs  []ot.Wire  // both labels for pubSeed||addr bits
	OutputHints   []ot.Wire
}

// GarblerSession is the garbler-side immutable state.
type GarblerSession struct {
	SessionID   uint64
	SenderSetup ot.COSenderSetup
}

// EvaluatorSession is the evaluator-side immutable state.
type EvaluatorSession struct {
	SessionID    uint64
	ChoiceBundle ot.COChoiceBundle
}
