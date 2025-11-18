package circuit

import (
	"fmt"

	"github.com/markkurossi/mpc/ot"
)

// LabelsForBits selects appropriate labels for the provided wires based on bits.
func LabelsForBits(wires []ot.Wire, bits []bool) ([]ot.Label, error) {
	if len(bits) != len(wires) {
		return nil, fmt.Errorf("wire/bit length mismatch: %d vs %d", len(wires), len(bits))
	}

	result := make([]ot.Label, len(bits))
	for i, bit := range bits {
		if bit {
			result[i] = wires[i].L1
		} else {
			result[i] = wires[i].L0
		}
	}

	return result, nil
}

// BitsFromLabels resolves concrete labels back to boolean outputs.
func BitsFromLabels(wires []ot.Wire, labels []ot.Label) ([]bool, error) {
	if len(wires) != len(labels) {
		return nil, fmt.Errorf("wire/label length mismatch: %d vs %d", len(wires), len(labels))
	}

	result := make([]bool, len(labels))
	for i := range labels {
		r, err := labelBit(wires[i], labels[i])
		if err != nil {
			return nil, err
		}
		result[i] = r
	}

	return result, nil
}

func labelBit(wire ot.Wire, label ot.Label) (bool, error) {
	switch {
	case label.Equal(wire.L0):
		return false, nil
	case label.Equal(wire.L1):
		return true, nil
	default:
		return false, fmt.Errorf("unknown label %s for wire %v", label, wire)
	}
}
