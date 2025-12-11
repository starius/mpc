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
	baseAddr.SetLayer(1)
	baseAddr.SetTree(0x0102030405060708)
	baseAddr.SetKeypair(0x0a0b0c0d)
	public := PublicData{PubSeed: pubSeed, Addr: baseAddr}

	circ, meta, err := CompileCircuit(public)
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}

	// Reference PK.
	ctx, err := NewContext(skSeed[:], pubSeed[:])
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	refPK := PublicKey(ctx, baseAddr)

	// 2PC rounds.
	msg1, gSess, err := GarblerRound1(rand.Reader, CurveP256, public, meta)
	if err != nil {
		t.Fatalf("GarblerRound1: %v", err)
	}
	msg2, eSess, err := EvaluatorRound2(rand.Reader, CurveP256, msg1, public, meta, skE)
	if err != nil {
		t.Fatalf("EvaluatorRound2: %v", err)
	}
	msg3, err := GarblerRound3(rand.Reader, CurveP256, circ, public, meta, gSess, skG, msg2)
	if err != nil {
		t.Fatalf("GarblerRound3: %v", err)
	}

	gotPK, err := EvaluatorRound4(CurveP256, circ, public, meta, eSess, msg3)
	if err != nil {
		t.Fatalf("EvaluatorRound4: %v", err)
	}

	if !bytes.Equal(refPK, gotPK) {
		t.Fatalf("pk mismatch")
	}
}
