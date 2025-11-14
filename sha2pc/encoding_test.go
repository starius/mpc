package sha2pc

import (
	"math/big"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

// TestRound1Encoding ensures Round1 payload encoding is lossless.
func TestRound1Encoding(t *testing.T) {
	payload := sampleRound1()
	data, err := EncodeRound1(payload)
	if err != nil {
		t.Fatalf("encodeRound1: %v", err)
	}
	got, err := DecodeRound1(data)
	if err != nil {
		t.Fatalf("decodeRound1: %v", err)
	}
	if !round1Equal(payload, got) {
		t.Fatalf("round1 mismatch\ngot  %#v\nwant %#v", got, payload)
	}
}

// TestRound2Encoding ensures Round2 payload encoding is lossless.
func TestRound2Encoding(t *testing.T) {
	payload := Round2Payload{
		Choices: []ot.ECPoint{
			{X: big.NewInt(1), Y: big.NewInt(2)},
			{X: big.NewInt(3), Y: big.NewInt(4)},
		},
	}
	data, err := EncodeRound2(payload)
	if err != nil {
		t.Fatalf("encodeRound2: %v", err)
	}
	got, err := DecodeRound2(data)
	if err != nil {
		t.Fatalf("decodeRound2: %v", err)
	}
	if !round2Equal(payload, got) {
		t.Fatalf("round2 mismatch")
	}
}

// TestRound3Encoding ensures Round3 payload encoding is lossless.
func TestRound3Encoding(t *testing.T) {
	payload := Round3Payload{
		Ciphertexts: []ot.LabelCiphertext{
			{
				Zero: newLabelData(1),
				One:  newLabelData(2),
			},
			{
				Zero: newLabelData(3),
				One:  newLabelData(4),
			},
		},
	}
	data, err := EncodeRound3(payload)
	if err != nil {
		t.Fatalf("encodeRound3: %v", err)
	}
	got, err := DecodeRound3(data)
	if err != nil {
		t.Fatalf("decodeRound3: %v", err)
	}
	if !round3Equal(payload, got) {
		t.Fatalf("round3 mismatch")
	}
}

// TestGarblerSessionEncoding ensures GarblerSession encoding is lossless.
func TestGarblerSessionEncoding(t *testing.T) {
	session := sampleGarblerSession()
	data, err := EncodeGarblerSession(session)
	if err != nil {
		t.Fatalf("EncodeGarblerSession: %v", err)
	}
	got, err := DecodeGarblerSession(data)
	if err != nil {
		t.Fatalf("DecodeGarblerSession: %v", err)
	}
	if !garblerSessionsEqual(session, got) {
		t.Fatalf("garbler session mismatch")
	}
}

// TestEvaluatorSessionEncoding ensures EvaluatorSession encoding is lossless.
func TestEvaluatorSessionEncoding(t *testing.T) {
	session := sampleEvaluatorSession()
	data, err := EncodeEvaluatorSession(session)
	if err != nil {
		t.Fatalf("EncodeEvaluatorSession: %v", err)
	}
	got, err := DecodeEvaluatorSession(data)
	if err != nil {
		t.Fatalf("DecodeEvaluatorSession: %v", err)
	}
	if !evaluatorSessionsEqual(session, got) {
		t.Fatalf("evaluator session mismatch")
	}
}

// sampleRound1 builds a small Round1Payload used in tests.
func sampleRound1() Round1Payload {
	var key [32]byte
	for i := 0; i < len(key); i++ {
		key[i] = byte(i)
	}

	return Round1Payload{
		Key: key,
		GarbledTables: [][]ot.Label{
			{sampleLabel(1), sampleLabel(2)},
			nil,
			{sampleLabel(3)},
		},
		GarblerInputs: []ot.Label{sampleLabel(10), sampleLabel(11)},
		OutputHints: []ot.Wire{
			{L0: sampleLabel(20), L1: sampleLabel(21)},
			{L0: sampleLabel(22), L1: sampleLabel(23)},
		},
		OT: OTSenderSetup{
			CurveName: "P-256",
			A: ot.ECPoint{
				X: big.NewInt(123),
				Y: big.NewInt(456),
			},
		},
	}
}

// sampleLabel creates a deterministic label for tests.
func sampleLabel(v uint64) ot.Label {
	return ot.Label{
		D0: v,
		D1: v + 100,
	}
}

// newLabelData creates deterministic label data for tests.
func newLabelData(seed byte) ot.LabelData {
	var d ot.LabelData
	for i := range d {
		d[i] = seed + byte(i)
	}

	return d
}

// round1Equal compares two Round1Payloads.
func round1Equal(a, b Round1Payload) bool {
	if a.Key != b.Key {
		return false
	}
	if !tablesEqual(a.GarbledTables, b.GarbledTables) {
		return false
	}
	if !labelsEqual(a.GarblerInputs, b.GarblerInputs) {
		return false
	}
	if !wiresEqual(a.OutputHints, b.OutputHints) {
		return false
	}

	return otSetupEqual(a.OT, b.OT)
}

// tablesEqual compares garbled table slices.
func tablesEqual(a, b [][]ot.Label) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !labelsEqual(a[i], b[i]) {
			return false
		}
	}

	return true
}

// labelsEqual compares label slices.
func labelsEqual(a, b []ot.Label) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].D0 != b[i].D0 || a[i].D1 != b[i].D1 {
			return false
		}
	}

	return true
}

// wiresEqual compares output wire slices.
func wiresEqual(a, b []ot.Wire) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].L0 != b[i].L0 || a[i].L1 != b[i].L1 {
			return false
		}
	}

	return true
}

// otSetupEqual compares OT setups.
func otSetupEqual(a, b OTSenderSetup) bool {
	if a.CurveName != b.CurveName {
		return false
	}
	if a.A.X.Cmp(b.A.X) != 0 || a.A.Y.Cmp(b.A.Y) != 0 {
		return false
	}

	return true
}

// round2Equal compares Round2 payloads.
func round2Equal(a, b Round2Payload) bool {
	if len(a.Choices) != len(b.Choices) {
		return false
	}
	for i := range a.Choices {
		if a.Choices[i].X.Cmp(b.Choices[i].X) != 0 ||
			a.Choices[i].Y.Cmp(b.Choices[i].Y) != 0 {
			return false
		}
	}

	return true
}

// round3Equal compares Round3 payloads.
func round3Equal(a, b Round3Payload) bool {
	if len(a.Ciphertexts) != len(b.Ciphertexts) {
		return false
	}
	for i := range a.Ciphertexts {
		if a.Ciphertexts[i].Zero != b.Ciphertexts[i].Zero ||
			a.Ciphertexts[i].One != b.Ciphertexts[i].One {
			return false
		}
	}

	return true
}

// sampleGarblerSession builds a representative GarblerSession for tests.
func sampleGarblerSession() *GarblerSession {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}

	return &GarblerSession{
		key: key,
		senderSetup: ot.COSenderSetup{
			CurveName: "P-256",
			Scalar:    big.NewInt(3),
			Ax:        big.NewInt(5),
			Ay:        big.NewInt(7),
			AaInvX:    big.NewInt(11),
			AaInvY:    big.NewInt(13),
		},
		wires: []ot.Wire{
			{L0: sampleLabel(30), L1: sampleLabel(31)},
			{L0: sampleLabel(32), L1: sampleLabel(33)},
		},
	}
}

// sampleEvaluatorSession builds a representative EvaluatorSession for tests.
func sampleEvaluatorSession() *EvaluatorSession {
	var key [32]byte
	for i := range key {
		key[i] = byte(2*i + 1)
	}

	return &EvaluatorSession{
		key: key,
		garbled: [][]ot.Label{
			{sampleLabel(40)},
			{sampleLabel(41), sampleLabel(42)},
		},
		outputHints: []ot.Wire{
			{L0: sampleLabel(50), L1: sampleLabel(51)},
		},
		wires: []ot.Label{sampleLabel(60), sampleLabel(61)},
		choiceBundle: ot.COChoiceBundle{
			CurveName: "P-256",
			Ax:        big.NewInt(17),
			Ay:        big.NewInt(19),
			Scalars: []*big.Int{
				big.NewInt(23),
				big.NewInt(29),
			},
			Bits: []bool{true, false},
		},
	}
}

// garblerSessionsEqual compares two garbler sessions.
func garblerSessionsEqual(a, b *GarblerSession) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.key != b.key {
		return false
	}
	if !cosenderEqual(a.senderSetup, b.senderSetup) {
		return false
	}

	return wiresEqual(a.wires, b.wires)
}

// evaluatorSessionsEqual compares two evaluator sessions.
func evaluatorSessionsEqual(a, b *EvaluatorSession) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.key != b.key {
		return false
	}
	if !tablesEqual(a.garbled, b.garbled) {
		return false
	}
	if !wiresEqual(a.outputHints, b.outputHints) {
		return false
	}
	if !labelsEqual(a.wires, b.wires) {
		return false
	}

	return choiceBundlesEqual(a.choiceBundle, b.choiceBundle)
}

// cosenderEqual compares two COSenderSetup values.
func cosenderEqual(a, b ot.COSenderSetup) bool {
	if a.CurveName != b.CurveName {
		return false
	}
	switch {
	case a.Scalar.Cmp(b.Scalar) != 0,
		a.Ax.Cmp(b.Ax) != 0,
		a.Ay.Cmp(b.Ay) != 0,
		a.AaInvX.Cmp(b.AaInvX) != 0,
		a.AaInvY.Cmp(b.AaInvY) != 0:

		return false
	}

	return true
}

// choiceBundlesEqual compares two COChoiceBundle values.
func choiceBundlesEqual(a, b ot.COChoiceBundle) bool {
	if a.CurveName != b.CurveName {
		return false
	}
	if a.Ax.Cmp(b.Ax) != 0 || a.Ay.Cmp(b.Ay) != 0 {
		return false
	}
	if len(a.Scalars) != len(b.Scalars) {
		return false
	}
	for i := range a.Scalars {
		if a.Scalars[i].Cmp(b.Scalars[i]) != 0 {
			return false
		}
	}
	if len(a.Bits) != len(b.Bits) {
		return false
	}
	for i := range a.Bits {
		if a.Bits[i] != b.Bits[i] {
			return false
		}
	}

	return true
}
