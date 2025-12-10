package wots2pc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestMPCPublicKey runs the 2PC flow to derive the WOTS+ public key and
// compares against the pure-Go reference.
func TestMPCPublicKey(t *testing.T) {
	var skSeed [32]byte
	if _, err := rand.Read(skSeed[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var skG [32]byte
	var skE [32]byte
	if _, err := rand.Read(skE[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	for i := 0; i < 32; i++ {
		skG[i] = skSeed[i] ^ skE[i]
	}
	var pubSeed [32]byte
	if _, err := rand.Read(pubSeed[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var baseAddr Address

	// Reference PK.
	ctx, err := NewContext(skSeed[:], pubSeed[:])
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	refPK := PublicKey(ctx, baseAddr)

	// 2PC rounds.
	msg1, gSess, err := GarblerRound1(rand.Reader, CurveP256)
	if err != nil {
		t.Fatalf("GarblerRound1: %v", err)
	}
	msg2, eSess, err := EvaluatorRound2(rand.Reader, CurveP256, msg1, skE)
	if err != nil {
		t.Fatalf("EvaluatorRound2: %v", err)
	}
	msg3, err := GarblerRound3(rand.Reader, CurveP256, gSess, skG, msg2)
	if err != nil {
		t.Fatalf("GarblerRound3: %v", err)
	}

	gotPK := make([]byte, len(refPK))
	for i := 0; i < SHA2_256sParams.Len; i++ {
		addr := baseAddr
		addr.SetChain(byte(i))
		elem, err := EvaluatorRound4(CurveP256, eSess, msg3, pubSeed, addr)
		if err != nil {
			t.Fatalf("EvaluatorRound4 chain %d: %v", i, err)
		}
		copy(gotPK[i*32:(i+1)*32], elem[:])
	}

	if !bytes.Equal(refPK, gotPK) {
		t.Fatalf("pk mismatch")
	}
}
