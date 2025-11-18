package sha2pc

import (
	crand "crypto/rand"
	"fmt"
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

	msg2, eState, err := EvaluatorRound2(crand.Reader, CurveP256, msg1, b)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round2 choices=%d\n", len(msg2.Choices))

	msg3, err := GarblerRound3(crand.Reader, CurveP256, gState, a, msg2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round3 ciphertexts=%d tables=%d\n",
		len(msg3.Ciphertexts), len(msg3.GarbledTables))

	hashEval, err := EvaluatorRound4(CurveP256, eState, msg3)
	if err != nil {
		panic(err)
	}
	fmt.Printf("round4 digest-prefix=%x\n", hashEval[:4])

	fmt.Printf("evaluator hash=%x\n", hashEval)

	// Output:
	// round1 curve=P-256
	// round2 choices=256
	// round3 ciphertexts=256 tables=127806
	// round4 digest-prefix=4b2f7457
	// evaluator hash=4b2f74579fc7c778745121996f604371a326dc5174f9851706032626668abf2e
}
