# wots2pc

This package implements Winternitz One-Time Signature Plus (WOTS+) for the
SPHINCS+ SHA2-256s/f parameter set (`n=32`, `w=16`, `len=67`) using SHA-256 as
the underlying hash. It currently contains a pure-Go WOTS+ implementation and
tests; MPC wiring will be added later while keeping these semantics fixed.
