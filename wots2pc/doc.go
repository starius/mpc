// Package wots2pc implements the SHA2-256s/f Winternitz One-Time Signature Plus
// (WOTS+) scheme with parameters n=32, w=16, len=67 from the SPHINCS+ SHA2
// families. The scheme follows SPHINCS+ conventions:
//   - sk_seed is secret and keyed into a PRF to generate chain starts.
//   - pub_seed is public and prepended to all tweakable hashes so its preimage
//     can be pre-absorbed (the reference code caches the hash state).
//   - address tweaks every hash call to keep chains distinct across the
//     hypertree (layer/tree/leaf/chain/hash indices).
//
// The initial version is pure Go and does not include MPC wiring; later work
// will add 2PC while keeping the inputs/outputs identical to the reference
// WOTS+.
package wots2pc
