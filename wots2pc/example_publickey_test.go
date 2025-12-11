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
	addr.SetLayer(2)
	addr.SetTree(0x1122334455667788)
	addr.SetKeypair(0x01020304)

	// Reference PK.
	ctx, err := NewContext(skSeed[:], pubSeed[:])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	refPK := PublicKey(ctx, addr)

	// 2PC: rounds mirror sha2pc.
	msg1, gState, err := GarblerRound1(crand.Reader, CurveP256)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	msg2, eState, err := EvaluatorRound2(crand.Reader, CurveP256, msg1, skE)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	msg3, err := GarblerRound3(crand.Reader, CurveP256, gState, skG, msg2)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	pk, err := EvaluatorRound4(CurveP256, eState, msg3, pubSeed, addr)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	fmt.Printf("match: %v\n", string(pk) == string(refPK))
	// Output:
	// match: true
}
