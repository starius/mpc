package wots2pc

import (
	"crypto/sha256"
	"errors"
)

// Context bundles the fixed parameters and seeds needed for WOTS+.
// sk_seed is secret (chain starts), pub_seed is public and hashes are
// domain-separated by the SPHINCS+ address so distinct chains never collide.
type Context struct {
	Params  Params
	SKSeed  [32]byte
	PubSeed [32]byte
}

// NewContext validates and returns a WOTS+ context for SHA2-256s/f. Both seeds
// must be exactly 32 bytes. pubSeed can be pre-absorbed by callers if they want
// to cache a hash state (the reference code’s state_seeded); here we simply
// prepend it for clarity.
func NewContext(skSeed, pubSeed []byte) (Context, error) {
	if len(skSeed) != SHA2_256sParams.N {
		return Context{}, errors.New("wots2pc: skSeed must be 32 bytes")
	}
	if len(pubSeed) != SHA2_256sParams.N {
		return Context{}, errors.New("wots2pc: pubSeed must be 32 bytes")
	}
	var ctx Context
	ctx.Params = SHA2_256sParams
	copy(ctx.SKSeed[:], skSeed)
	copy(ctx.PubSeed[:], pubSeed)
	return ctx, nil
}

// baseW converts an input byte string to base-w digits.
func baseW(params Params, out []uint8, input []byte) {
	in := 0
	bits := 0
	var total uint8
	for i := 0; i < len(out); i++ {
		if bits == 0 {
			total = input[in]
			in++
			bits = 8
		}
		bits -= params.LogW
		out[i] = (total >> bits) & uint8(params.W-1)
	}
}

// wotsChecksum computes the checksum digits over the base-w message.
func wotsChecksum(params Params, out []uint8, msgBaseW []uint8) {
	csum := 0
	for i := 0; i < params.Len1; i++ {
		csum += params.W - 1 - int(msgBaseW[i])
	}
	shift := (8 - ((params.Len2 * params.LogW) % 8)) % 8
	csum <<= shift
	csumBytes := make([]byte, (params.Len2*params.LogW+7)/8)
	for i := len(csumBytes) - 1; i >= 0; i-- {
		csumBytes[i] = byte(csum & 0xff)
		csum >>= 8
	}
	baseW(params, out, csumBytes)
}

func chainLengths(params Params, msg []byte) ([]uint8, error) {
	if len(msg) != params.N {
		return nil, errors.New("wots2pc: message must be 32 bytes")
	}
	lengths := make([]uint8, params.Len)
	msgBase := lengths[:params.Len1]
	baseW(params, msgBase, msg)
	csumDigits := lengths[params.Len1:]
	wotsChecksum(params, csumDigits, msgBase)
	return lengths, nil
}

// ChainLengths exposes the base-w chain lengths for SHA2-256s/f WOTS+.
func ChainLengths(msg []byte) ([]uint8, error) {
	return chainLengths(SHA2_256sParams, msg)
}

// prfAddr implements PRF(pk_seed, sk_seed, addr). pubSeed is public but keyed
// in to allow precomputation and domain separation.
func prfAddr(params Params, pubSeed, skSeed []byte, addr Address) [32]byte {
	h := sha256.New()
	h.Write(pubSeed)
	h.Write(addr[:])
	h.Write(skSeed)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// thash hashes inblocks of length n with pub_seed and addr tweaks.
func thash(params Params, pubSeed []byte, addr Address, in []byte) [32]byte {
	h := sha256.New()
	h.Write(pubSeed)
	h.Write(addr[:])
	h.Write(in)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// genChain iterates the hash chain for the requested steps.
func genChain(params Params, out, in []byte, start, steps int, pubSeed []byte, addr Address) {
	copy(out, in)
	for i := start; i < start+steps && i < params.W; i++ {
		addr.SetHash(uint8(i))
		block := thash(params, pubSeed, addr, out[:params.N])
		copy(out, block[:])
	}
}

// PublicKey derives the WOTS+ public key for the given address.
func PublicKey(ctx Context, baseAddr Address) []byte {
	params := ctx.Params
	pk := make([]byte, params.Len*params.N)
	for i := 0; i < params.Len; i++ {
		addr := baseAddr.Copy()
		addr.SetChain(uint8(i))
		addr.SetHash(0)
		addr.SetType(addrTypeWOTSPRF)
		secret := prfAddr(params, ctx.PubSeed[:], ctx.SKSeed[:], addr)
		addr.SetType(addrTypeWOTS)
		genChain(params, pk[i*params.N:(i+1)*params.N], secret[:], 0, params.W-1, ctx.PubSeed[:], addr)
	}
	return pk
}

// Sign creates a WOTS+ signature of msg under the given address.
func Sign(ctx Context, baseAddr Address, msg []byte) ([]byte, error) {
	params := ctx.Params
	lengths, err := chainLengths(params, msg)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, params.Len*params.N)
	for i := 0; i < params.Len; i++ {
		addr := baseAddr.Copy()
		addr.SetChain(uint8(i))
		addr.SetHash(0)
		addr.SetType(addrTypeWOTSPRF)
		secret := prfAddr(params, ctx.PubSeed[:], ctx.SKSeed[:], addr)
		addr.SetType(addrTypeWOTS)
		genChain(params, sig[i*params.N:(i+1)*params.N], secret[:], 0, int(lengths[i]), ctx.PubSeed[:], addr)
	}
	return sig, nil
}

// PublicKeyFromSignature derives the WOTS+ public key from a signature and msg.
func PublicKeyFromSignature(ctx Context, baseAddr Address, msg []byte, sig []byte) ([]byte, error) {
	params := ctx.Params
	if len(sig) != params.Len*params.N {
		return nil, errors.New("wots2pc: signature length mismatch")
	}
	lengths, err := chainLengths(params, msg)
	if err != nil {
		return nil, err
	}
	pk := make([]byte, params.Len*params.N)
	for i := 0; i < params.Len; i++ {
		addr := baseAddr.Copy()
		addr.SetChain(uint8(i))
		addr.SetType(addrTypeWOTS)
		start := int(lengths[i])
		steps := params.W - 1 - start
		genChain(params, pk[i*params.N:(i+1)*params.N], sig[i*params.N:(i+1)*params.N], start, steps, ctx.PubSeed[:], addr)
	}
	return pk, nil
}

// Verify returns true if sig verifies against the provided public key.
func Verify(ctx Context, baseAddr Address, msg, sig, pk []byte) bool {
	expected, err := PublicKeyFromSignature(ctx, baseAddr, msg, sig)
	if err != nil {
		return false
	}
	return subtleConstantTimeCompare(expected, pk)
}

// subtleConstantTimeCompare compares byte slices in constant time.
func subtleConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v uint8
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
