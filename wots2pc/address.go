package wots2pc

import "encoding/binary"

// Address encodes the SPHINCS+ address structure used to domain-separate
// hash invocations. It mirrors the SHA2 address layout in the reference code
// so each chain step is unique within the hypertree (layer/tree/leaf/chain/hash).
type Address [32]byte

// SetLayer sets the Merkle layer field.
func (a *Address) SetLayer(layer uint8) {
	a[addrOffsetLayer] = layer
}

// SetTree sets the subtree identifier.
func (a *Address) SetTree(tree uint64) {
	binary.BigEndian.PutUint64(a[addrOffsetTree:], tree)
}

// SetType sets the address type (WOTS, WOTSPRF, etc.).
func (a *Address) SetType(t uint8) {
	a[addrOffsetType] = t
}

// SetKeypair sets the leaf/keypair index.
func (a *Address) SetKeypair(keypair uint32) {
	binary.BigEndian.PutUint32(a[addrOffsetKeypair:], keypair)
}

// SetChain sets the Winternitz chain index.
func (a *Address) SetChain(chain uint8) {
	a[addrOffsetChain] = chain
}

// SetHash sets the position within a chain.
func (a *Address) SetHash(hash uint8) {
	a[addrOffsetHash] = hash
}

// Copy returns a shallow copy of the address bytes.
func (a *Address) Copy() Address {
	var out Address
	copy(out[:], a[:])
	return out
}
