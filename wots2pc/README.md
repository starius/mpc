# wots2pc

This package implements Winternitz One-Time Signature Plus (WOTS+) for the
SPHINCS+ SHA2-256s/f parameter set (`n=32`, `w=16`, `len=67`) using SHA-256 as
the underlying hash. It currently contains a pure-Go WOTS+ implementation and
tests; MPC wiring will be added later while keeping these semantics fixed.

## 2PC public key derivation

The 2PC API mirrors `sha2pc` with four rounds. The garbler and evaluator hold
XOR shares of the 32-byte `sk_seed` (`skG ^ skE = sk_seed`). `pub_seed` and the
address are public and supplied by the garbler as public inputs.

```go
var skSeed, skG, skE, pubSeed [32]byte
// populate seeds...
for i := 0; i < 32; i++ { skG[i] = skSeed[i] ^ skE[i] }

var addr wots2pc.Address // fill layer/tree/keypair/chain as needed

// Pure Go reference
ctx, _ := wots2pc.NewContext(skSeed[:], pubSeed[:])
refPK := wots2pc.PublicKey(ctx, addr)

// 2PC flow (public-key only)
msg1, gState, _ := wots2pc.GarblerRound1(crand.Reader, wots2pc.CurveP256)
msg2, eState, _ := wots2pc.EvaluatorRound2(crand.Reader, wots2pc.CurveP256, msg1, skE)
msg3, _ := wots2pc.GarblerRound3(crand.Reader, wots2pc.CurveP256, gState, skG, msg2)

pk := make([]byte, len(refPK))
for i := 0; i < wots2pc.SHA2_256sParams.Len; i++ {
    a := addr
    a.SetChain(byte(i))
    elem, _ := wots2pc.EvaluatorRound4(wots2pc.CurveP256, eState, msg3, pubSeed, a)
    copy(pk[i*32:(i+1)*32], elem[:])
}
// pk matches refPK
```

Signatures will reuse the same pattern; only the public message digest becomes
an evaluator input. Further optimizations (public midstates, smaller circuits)
can be layered later without changing the API.
