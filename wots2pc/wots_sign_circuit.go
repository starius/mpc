package wots2pc

import (
	"bytes"
	_ "embed"

	"github.com/markkurossi/mpc/circuit"
)

// wotsSignCircuitBlob stores the compiled WOTS+ signature circuit.
//
//go:embed wots_sign.mpclc
var wotsSignCircuitBlob []byte

// wotsSignCircuit holds the parsed circuit singleton.
var wotsSignCircuit = func() *circuit.Circuit {
	circ, err := circuit.ParseMPCLC(bytes.NewReader(wotsSignCircuitBlob))
	if err != nil {
		panic(err)
	}
	return circ
}()
