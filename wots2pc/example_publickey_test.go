package wots2pc

import (
	crand "crypto/rand"
	"fmt"
)

// Example demonstrating 2PC public-key derivation matching the pure Go WOTS+ PK.
func Example_publicKey2PC() {
	var skSeed [32]byte
	var skG [32]byte
	var skE [32]byte
	var pubSeed [32]byte
	for i := 0; i < 32; i++ {
		skG[i] = byte(i + 1)
		skE[i] = byte(255 - i)
		skSeed[i] = skG[i] ^ skE[i]
		pubSeed[i] = byte(0xa0 + i)
	}
	var addr Address

	// Reference PK.
	ctx, _ := NewContext(skSeed[:], pubSeed[:])
	refPK := PublicKey(ctx, addr)

	// 2PC: rounds mirror sha2pc.
	msg1, gState, _ := GarblerRound1(crand.Reader, CurveP256)
	msg2, eState, _ := EvaluatorRound2(crand.Reader, CurveP256, msg1, skE)
	msg3, _ := GarblerRound3(crand.Reader, CurveP256, gState, skG, msg2)

	pk := make([]byte, len(refPK))
	for i := 0; i < SHA2_256sParams.Len; i++ {
		a := addr
		a.SetChain(byte(i))
		elem, _ := EvaluatorRound4(CurveP256, eState, msg3, pubSeed, a)
		copy(pk[i*32:(i+1)*32], elem[:])
	}

	fmt.Printf("match: %v\n", string(pk) == string(refPK))
	// Output:
	// match: true
}
