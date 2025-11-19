package sha2pc

import (
	crand "crypto/rand"
	"fmt"
	"testing"
)

// Example demonstrates running every round and inspecting the payloads.
func Example() {
	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}

	msg1, gState, err := GarblerRound1(crand.Reader, CurveP256)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round1 curve=%s\n", msg1.OT.CurveName)
	r1Bytes, err := EncodeRound1(msg1)
	if err != nil {
		panic(err)
	}
	gSessionBytes, err := EncodeGarblerSession(gState)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round1 encode=%d session=%d\n", len(r1Bytes), len(gSessionBytes))

	msg2, eState, err := EvaluatorRound2(crand.Reader, CurveP256, msg1, b)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round2 choices=%d\n", len(msg2.Choices))
	r2Bytes, err := EncodeRound2(msg2)
	if err != nil {
		panic(err)
	}
	eSessionBytes, err := EncodeEvaluatorSession(eState)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round2 encode=%d session=%d\n", len(r2Bytes), len(eSessionBytes))

	msg3, err := GarblerRound3(crand.Reader, CurveP256, gState, a, msg2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round3 ciphertexts=%d tables=%d\n",
		len(msg3.Ciphertexts), len(msg3.GarbledTables))
	r3Bytes, err := EncodeRound3(msg3)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round3 encode=%d\n", len(r3Bytes))

	hashEval, err := EvaluatorRound4(CurveP256, eState, msg3)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round4 digest-prefix=%x\n", hashEval[:4])

	fmt.Printf("evaluator hash=%x\n", hashEval)

	// Output:
	// round1 curve=P-256
	// round1 encode=87 session=195
	// round2 choices=256
	// round2 encode=8234 session=8319
	// round3 ciphertexts=256 tables=127806
	// round3 encode=1218390
	// round4 digest-prefix=4b2f7457
	// evaluator hash=4b2f74579fc7c778745121996f604371a326dc5174f9851706032626668abf2e
}

// TestExampleSizes mirrors the Example but asserts the encoded sizes remain at
// their expected values.
func TestExampleSizes(t *testing.T) {
	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}

	msg1, gState, err := GarblerRound1(crand.Reader, CurveP256)
	if err != nil {
		t.Fatalf("GarblerRound1: %v", err)
	}
	r1Bytes, err := EncodeRound1(msg1)
	if err != nil {
		t.Fatalf("EncodeRound1: %v", err)
	}
	gSessionBytes, err := EncodeGarblerSession(gState)
	if err != nil {
		t.Fatalf("EncodeGarblerSession: %v", err)
	}

	msg2, eState, err := EvaluatorRound2(crand.Reader, CurveP256, msg1, b)
	if err != nil {
		t.Fatalf("EvaluatorRound2: %v", err)
	}
	r2Bytes, err := EncodeRound2(msg2)
	if err != nil {
		t.Fatalf("EncodeRound2: %v", err)
	}
	eSessionBytes, err := EncodeEvaluatorSession(eState)
	if err != nil {
		t.Fatalf("EncodeEvaluatorSession: %v", err)
	}

	msg3, err := GarblerRound3(crand.Reader, CurveP256, gState, a, msg2)
	if err != nil {
		t.Fatalf("GarblerRound3: %v", err)
	}
	r3Bytes, err := EncodeRound3(msg3)
	if err != nil {
		t.Fatalf("EncodeRound3: %v", err)
	}

	const (
		expRound1Payload = 87
		expGarblerSess   = 195
		expRound2Payload = 8234
		expEvalSess      = 8319
		expRound3Payload = 1218390
	)

	if got := len(r1Bytes); got != expRound1Payload {
		t.Fatalf("round1 payload length mismatch: got %d want %d", got, expRound1Payload)
	}
	if got := len(gSessionBytes); got != expGarblerSess {
		t.Fatalf("garbler session length mismatch: got %d want %d", got, expGarblerSess)
	}
	if got := len(r2Bytes); got != expRound2Payload {
		t.Fatalf("round2 payload length mismatch: got %d want %d", got, expRound2Payload)
	}
	if got := len(eSessionBytes); got != expEvalSess {
		t.Fatalf("evaluator session length mismatch: got %d want %d", got, expEvalSess)
	}
	if got := len(r3Bytes); got != expRound3Payload {
		t.Fatalf("round3 payload length mismatch: got %d want %d", got, expRound3Payload)
	}
}
