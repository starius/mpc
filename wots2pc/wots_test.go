package wots2pc

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestChainLengths checks the base-w expansion and checksum against a known vector.
func TestChainLengths(t *testing.T) {
	msg := make([]byte, 32)
	for i := 0; i < len(msg); i++ {
		msg[i] = byte(i)
	}
	got, err := ChainLengths(msg)
	if err != nil {
		t.Fatalf("ChainLengths: %v", err)
	}
	want := []uint8{
		0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7,
		0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15,
		1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 1, 5, 1, 6, 1, 7,
		1, 8, 1, 9, 1, 10, 1, 11, 1, 12, 1, 13, 1, 14, 1, 15,
		2, 12, 0,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ChainLengths mismatch\n got: %v\nwant: %v", got, want)
	}
}

// TestSignAndPublicKey validates sign -> pk-from-sig roundtrip and fixed digests.
func TestSignAndPublicKey(t *testing.T) {
	var skSeed, pubSeed [32]byte
	for i := 0; i < 32; i++ {
		skSeed[i] = byte(i)
		pubSeed[i] = byte(0xff - i)
	}
	ctx, err := NewContext(skSeed[:], pubSeed[:])
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	var addr Address
	addr.SetLayer(3)
	addr.SetTree(0x0102030405060708)
	addr.SetKeypair(0x090a0b0c)

	msg := make([]byte, 32)
	for i := 0; i < 32; i++ {
		msg[i] = byte(0x20 + i)
	}

	sig, err := Sign(ctx, addr, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ctx.Params.Len*ctx.Params.N {
		t.Fatalf("signature length %d", len(sig))
	}
	pk := PublicKey(ctx, addr)
	pkFromSig, err := PublicKeyFromSignature(ctx, addr, msg, sig)
	if err != nil {
		t.Fatalf("PublicKeyFromSignature: %v", err)
	}
	if !bytes.Equal(pk, pkFromSig) {
		t.Fatalf("pkFromSig mismatch")
	}

	sigHash := sha256.Sum256(sig)
	pkHash := sha256.Sum256(pk)
	wantSig := [32]byte{0x2a, 0x1d, 0x02, 0x7c, 0x3e, 0x39, 0x9d, 0x53, 0xc5, 0x49, 0xab, 0xff, 0x16, 0x15, 0xf0, 0x89, 0x6d, 0x31, 0x84, 0x2e, 0x91, 0x8a, 0x57, 0x98, 0xd6, 0x22, 0x42, 0x51, 0x93, 0xd7, 0xa9, 0x6f}
	wantPK := [32]byte{0x83, 0x9c, 0x87, 0xa8, 0x56, 0xeb, 0xb8, 0x4e, 0x71, 0xda, 0x97, 0xf3, 0x7f, 0xa7, 0xc6, 0xa0, 0xe4, 0x31, 0x90, 0xc8, 0x8e, 0x98, 0x07, 0x7d, 0xa8, 0x66, 0x87, 0xdb, 0x0f, 0x22, 0x3a, 0xe8}
	if sigHash != wantSig {
		t.Fatalf("signature digest mismatch\ngot %x\nwant %x", sigHash, wantSig)
	}
	if pkHash != wantPK {
		t.Fatalf("pk digest mismatch\ngot %x\nwant %x", pkHash, wantPK)
	}
}

// TestVerify exercises verification success and failure.
func TestVerify(t *testing.T) {
	var skSeed, pubSeed [32]byte
	for i := 0; i < 32; i++ {
		skSeed[i] = byte(i)
		pubSeed[i] = byte(0xff - i)
	}
	ctx, err := NewContext(skSeed[:], pubSeed[:])
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	var addr Address
	msg := bytes.Repeat([]byte{0x42}, 32)
	sig, err := Sign(ctx, addr, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pk := PublicKey(ctx, addr)

	if !Verify(ctx, addr, msg, sig, pk) {
		t.Fatalf("valid signature rejected")
	}
	sig[0] ^= 0xff
	if Verify(ctx, addr, msg, sig, pk) {
		t.Fatalf("tampered signature accepted")
	}
}
