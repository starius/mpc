package wots2pc

import (
	"bytes"
	_ "embed"

	"github.com/markkurossi/mpc/circuit"
)

// wotsPKCircuitBlob stores the compiled WOTS+ public key circuit.
//
//go:embed wots_pk.mpclc
var wotsPKCircuitBlob []byte

// wotsPKCircuit holds the parsed circuit singleton.
var wotsPKCircuit = func() *circuit.Circuit {
	circ, err := circuit.ParseMPCLC(bytes.NewReader(wotsPKCircuitBlob))
	if err != nil {
		panic(err)
	}
	return circ
}()
