package wots2pc

// Params captures the fixed WOTS+ parameters for a given SPHINCS+ set.
type Params struct {
	N    int // bytes per element
	W    int // Winternitz base
	LogW int // log2(W)
	Len1 int // message length in base-w digits
	Len2 int // checksum length in base-w digits
	Len  int // total digits
}

// SHA2_256sParams matches the SPHINCS+ SHA2-256s/f WOTS+ instance:
// n=32, w=16, len=67.
var SHA2_256sParams = Params{
	N:    32,
	W:    16,
	LogW: 4,
	Len1: 64,
	Len2: 3,
	Len:  67,
}

// Address constants copied from SPHINCS+ SHA2 offset layout.
const (
	addrTypeWOTS    = 0
	addrTypeWOTSPRF = 5

	addrOffsetLayer      = 0
	addrOffsetTree       = 1
	addrOffsetType       = 9
	addrOffsetKeypair    = 10
	addrOffsetChain      = 17
	addrOffsetHash       = 21
	addrOffsetTreeHeight = 17
	addrOffsetTreeIndex  = 18
)
