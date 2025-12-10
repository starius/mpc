package wots2pc

import (
	"bytes"
	_ "embed"

	"github.com/markkurossi/mpc/circuit"
)

// wotsChainCircuitBlob stores the compiled single-chain WOTS+ circuit.
//
//go:embed wots_chain.mpclc
var wotsChainCircuitBlob []byte

// wotsChainCircuit holds the parsed circuit singleton.
var wotsChainCircuit = func() *circuit.Circuit {
	circ, err := circuit.ParseMPCLC(bytes.NewReader(wotsChainCircuitBlob))
	if err != nil {
		panic(err)
	}
	return circ
}()
