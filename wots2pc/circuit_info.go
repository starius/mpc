package wots2pc

import (
	"fmt"

	"github.com/markkurossi/mpc/circuit"
)

type circuitInfo struct {
	GarblerBits   int
	EvaluatorBits int
	OutputBits    int
	TableLabels   int
	TotalWires    int
}

func deriveInfo(circ *circuit.Circuit) (circuitInfo, error) {
	if circ.NumParties() != 2 {
		return circuitInfo{}, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}
	if len(circ.Inputs) != 2 {
		return circuitInfo{}, fmt.Errorf("unexpected input sets: %d", len(circ.Inputs))
	}
	info := circuitInfo{
		GarblerBits:   int(circ.Inputs[0].Type.Bits),
		EvaluatorBits: int(circ.Inputs[1].Type.Bits),
		OutputBits:    circ.Outputs.Size(),
		TotalWires:    int(circ.NumWires),
	}
	var labels int
	for _, gate := range circ.Gates {
		count, err := gateCiphertextCount(gate.Op)
		if err != nil {
			return circuitInfo{}, err
		}
		labels += count
	}
	info.TableLabels = labels
	return info, nil
}
