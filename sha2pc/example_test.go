package sha2pc

import (
	"fmt"
	"math/rand"
)

// Example demonstrates running every round with deterministic inputs.
func Example() {
	garbler, _ := NewGarbler(&Config{Rand: rand.New(rand.NewSource(1))})
	evaluator, _ := NewEvaluator(&Config{Rand: rand.New(rand.NewSource(2))})

	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}

	msg1, _ := garbler.Round1(a)
	fmt.Println("round1 complete")

	msg2, _ := evaluator.Round2(msg1, b)
	fmt.Println("round2 complete")

	msg3, _ := garbler.Round3(msg2)
	fmt.Println("round3 complete")

	hashEval, msg4, _ := evaluator.Round4(msg3)
	fmt.Println("round4 complete")

	hashGar, _ := garbler.Finalize(msg4)
	fmt.Printf("evaluator hash=%x\n", hashEval)
	fmt.Printf("garbler hash=%x\n", hashGar)

	// Output:
	// round1 complete
	// round2 complete
	// round3 complete
	// round4 complete
	// evaluator hash=4b2f74579fc7c778745121996f604371a326dc5174f9851706032626668abf2e
	// garbler hash=4b2f74579fc7c778745121996f604371a326dc5174f9851706032626668abf2e
}
