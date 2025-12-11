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
for i := 0; i < 32; i++ {
    skG[i] = byte(i + 1)
    skE[i] = byte(255 - i)
    skSeed[i] = skG[i] ^ skE[i]
    pubSeed[i] = byte(0xa0 + i)
}
var addr wots2pc.Address // fill layer/tree/keypair/chain as needed
addr.SetLayer(2)
addr.SetTree(0x1122334455667788)
addr.SetKeypair(0x01020304)
public := wots2pc.PublicData{PubSeed: pubSeed, Addr: addr}
circ, meta, _ := wots2pc.CompileCircuit(public)

// Pure Go reference
ctx, _ := wots2pc.NewContext(skSeed[:], pubSeed[:])
refPK := wots2pc.PublicKey(ctx, addr)

// 2PC flow (public-key only)
msg1, gState, _ := wots2pc.GarblerRound1(crand.Reader, wots2pc.CurveP256, public, meta)
msg2, eState, _ := wots2pc.EvaluatorRound2(crand.Reader, wots2pc.CurveP256, msg1, public, meta, skE)
msg3, _ := wots2pc.GarblerRound3(crand.Reader, wots2pc.CurveP256, circ, public, meta, gState, skG, msg2)

pk, _ := wots2pc.EvaluatorRound4(wots2pc.CurveP256, circ, public, meta, eState, msg3)
// pk matches refPK
```

Signatures will reuse the same pattern; only the public message digest becomes
an evaluator input. Further optimizations (public midstates, smaller circuits)
can be layered later without changing the API.
