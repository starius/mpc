package sha2pc

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

// TestRound1Encoding ensures Round1 payload encoding is lossless.
func TestRound1Encoding(t *testing.T) {
	payload := sampleRound1()
	data, err := EncodeRound1(CurveP256, payload)
	if err != nil {
		t.Fatalf("encodeRound1: %v", err)
	}
	got, err := DecodeRound1(CurveP256, data)
	if err != nil {
		t.Fatalf("decodeRound1: %v", err)
	}
	if !round1Equal(payload, got) {
		t.Fatalf("round1 mismatch\ngot  %#v\nwant %#v", got, payload)
	}
}

// TestRound2Encoding ensures Round2 payload encoding is lossless.
func TestRound2Encoding(t *testing.T) {
	curve := CurveP256
	if curve == nil {
		t.Fatalf("CurveP256 is nil")
	}
	gx := new(big.Int).Set(curve.Params().Gx)
	gy := new(big.Int).Set(curve.Params().Gy)
	x2, y2 := curve.ScalarBaseMult([]byte{2})
	payload := Round2Payload{
		CurveName: curve.Params().Name,
		Choices: []ot.ECPoint{
			{X: gx, Y: gy},
			{X: new(big.Int).Set(x2), Y: new(big.Int).Set(y2)},
		},
	}
	data, err := EncodeRound2(CurveP256, payload)
	if err != nil {
		t.Fatalf("encodeRound2: %v", err)
	}
	got, err := DecodeRound2(CurveP256, data)
	if err != nil {
		t.Fatalf("decodeRound2: %v", err)
	}
	if !round2Equal(payload, got) {
		t.Fatalf("round2 mismatch")
	}
}

// TestRound3Encoding ensures Round3 payload encoding is lossless.
func TestRound3Encoding(t *testing.T) {
	payload := sampleRound3()
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
	data, err := EncodeGarblerSession(CurveP256, session)
	if err != nil {
		t.Fatalf("EncodeGarblerSession: %v", err)
	}
	got, err := DecodeGarblerSession(CurveP256, data)
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
	data, err := EncodeEvaluatorSession(CurveP256, session)
	if err != nil {
		t.Fatalf("EncodeEvaluatorSession: %v", err)
	}
	got, err := DecodeEvaluatorSession(CurveP256, data)
	if err != nil {
		t.Fatalf("DecodeEvaluatorSession: %v", err)
	}
	if !evaluatorSessionsEqual(session, got) {
		t.Fatalf("evaluator session mismatch")
	}
}

// TestCurveByteLen verifies curveByteLen returns correct sizes.
func TestCurveByteLen(t *testing.T) {
	cases := []struct {
		curve elliptic.Curve
		want  int
	}{
		{elliptic.P224(), 28},
		{elliptic.P256(), 32},
		{elliptic.P384(), 48},
		{elliptic.P521(), 66},
	}
	for _, tc := range cases {
		got, err := curveByteLen(tc.curve)
		if err != nil {
			t.Fatalf("curveByteLen(%s): %v", tc.curve.Params().Name, err)
		}
		if got != tc.want {
			t.Fatalf("curveByteLen(%s) = %d want %d", tc.curve.Params().Name, got, tc.want)
		}
	}
	if _, err := curveByteLen(nil); err != errNilCurve {
		t.Fatalf("curveByteLen(nil) = %v want errNilCurve", err)
	}
}

// sampleRound1 builds a small Round1Payload used in tests.
func sampleRound1() Round1Payload {
	return Round1Payload{
		OT: OTSenderSetup{
			CurveName: "P-256",
			A: ot.ECPoint{
				X: big.NewInt(123),
				Y: big.NewInt(456),
			},
		},
	}
}

// sampleRound3 builds a representative Round3 payload for tests.
func sampleRound3() Round3Payload {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	return Round3Payload{
		Ciphertexts: []ot.LabelCiphertext{
			{Zero: newLabelData(1), One: newLabelData(2)},
			{Zero: newLabelData(3), One: newLabelData(4)},
		},
		Key: key,
		GarbledTables: [][]ot.Label{
			{sampleLabel(10), sampleLabel(11)},
			{sampleLabel(12)},
		},
		GarblerInputs: []ot.Label{
			sampleLabel(20), sampleLabel(21),
		},
		OutputHints: []ot.Wire{
			{L0: sampleLabel(30), L1: sampleLabel(31)},
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
	if a.CurveName != b.CurveName {
		return false
	}
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
	if a.Key != b.Key {
		return false
	}
	if !labelsEqual(a.GarblerInputs, b.GarblerInputs) ||
		!tablesEqual(a.GarbledTables, b.GarbledTables) ||
		!wiresEqual(a.OutputHints, b.OutputHints) {
		return false
	}
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
	return &GarblerSession{
		senderSetup: ot.COSenderSetup{
			CurveName: "P-256",
			Scalar:    big.NewInt(3),
			Ax:        big.NewInt(5),
			Ay:        big.NewInt(7),
			AaInvX:    big.NewInt(11),
			AaInvY:    big.NewInt(13),
		},
	}
}

// sampleEvaluatorSession builds a representative EvaluatorSession for tests.
func sampleEvaluatorSession() *EvaluatorSession {
	return &EvaluatorSession{
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
	return cosenderEqual(a.senderSetup, b.senderSetup)
}

// evaluatorSessionsEqual compares two evaluator sessions.
func evaluatorSessionsEqual(a, b *EvaluatorSession) bool {
	if a == nil || b == nil {
		return a == b
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
