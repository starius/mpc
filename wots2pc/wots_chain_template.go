package wots2pc

const wotsChainTemplate = `// -*- go -*-

package main

import (
    "crypto/sha256"
)

const (
    wotsN    = 32
    wotsW    = 16

    addrTypeWOTS    = 0
    addrTypeWOTSPRF = 5

    addrOffsetType  = 9
    addrOffsetChain = 17
    addrOffsetHash  = 21
)

type Address [32]byte

type GarblerInput struct {
    SkSeed [wotsN]byte
    Chain  byte
}

var pubSeed = %[1]s
var baseAddr = %[2]s

func prfAddr(skSeed [wotsN]byte, chain byte) [wotsN]byte {
    var buf [wotsN + 32 + wotsN]byte
    for i := 0; i < wotsN; i++ {
        buf[i] = pubSeed[i]
    }
    addr := baseAddr
    addr[addrOffsetChain] = chain
    addr[addrOffsetHash] = 0
    addr[addrOffsetType] = addrTypeWOTSPRF
    for i := 0; i < 32; i++ {
        buf[wotsN+i] = addr[i]
    }
    for i := 0; i < wotsN; i++ {
        buf[wotsN+32+i] = skSeed[i]
    }
    return sha256.Sum256(buf[:])
}

func thash(in [wotsN]byte, chain byte, hash byte) [wotsN]byte {
    var buf [wotsN + 32 + wotsN]byte
    for i := 0; i < wotsN; i++ {
        buf[i] = pubSeed[i]
    }
    addr := baseAddr
    addr[addrOffsetChain] = chain
    addr[addrOffsetHash] = hash
    addr[addrOffsetType] = addrTypeWOTS
    for i := 0; i < 32; i++ {
        buf[wotsN+i] = addr[i]
    }
    for i := 0; i < wotsN; i++ {
        buf[wotsN+32+i] = in[i]
    }
    return sha256.Sum256(buf[:])
}

// main computes one WOTS+ chain endpoint: PRF start then 15 THash steps.
// Inputs:
//  garbler: skSeedG, chain; evaluator: skSeedE.
func main(g GarblerInput, skSeedE [wotsN]byte) [wotsN]byte {
    var skSeed [wotsN]byte
    for i := 0; i < wotsN; i++ {
        skSeed[i] = g.SkSeed[i] ^ skSeedE[i]
    }

    x := prfAddr(skSeed, g.Chain)
    for step := 0; step < wotsW-1; step++ {
        x = thash(x, g.Chain, byte(step))
    }
    return x
}
`
