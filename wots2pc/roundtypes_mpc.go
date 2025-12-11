package wots2pc

import "github.com/markkurossi/mpc/ot"

// Round1Payload carries OT setup from garbler.
type Round1Payload struct {
	SessionID uint64
	OT        OTSenderSetup
	Public    PublicData
	Meta      CircuitMeta
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
	Public    PublicData
	Meta      CircuitMeta
}

// Round3Payload bundles the garbled circuit and labels.
type Round3Payload struct {
	SessionID     uint64
	Ciphertexts   []ot.LabelCiphertext
	Key           [32]byte
	GarbledTables [][]ot.Label
	GarblerInputs []ot.Label // for skSeedG bits
	PublicInputs  []ot.Wire
	OutputHints   []ot.Wire
	Public        PublicData
	Meta          CircuitMeta
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
