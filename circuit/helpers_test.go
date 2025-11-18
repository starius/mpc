package circuit

import (
	"testing"

	"github.com/markkurossi/mpc/ot"
)

func TestLabelsForBits(t *testing.T) {
	wires := []ot.Wire{
		{L0: ot.Label{D0: 1}, L1: ot.Label{D0: 2}},
		{L0: ot.Label{D0: 3}, L1: ot.Label{D0: 4}},
	}
	bits := []bool{false, true}

	labels, err := LabelsForBits(wires, bits)
	if err != nil {
		t.Fatalf("LabelsForBits: %v", err)
	}
	if labels[0].D0 != 1 || labels[1].D0 != 4 {
		t.Fatalf("label mismatch: %#v", labels)
	}
}

func TestBitsFromLabels(t *testing.T) {
	wires := []ot.Wire{
		{L0: ot.Label{D0: 10}, L1: ot.Label{D0: 20}},
	}
	labels := []ot.Label{wires[0].L1}

	bits, err := BitsFromLabels(wires, labels)
	if err != nil {
		t.Fatalf("BitsFromLabels: %v", err)
	}
	if len(bits) != 1 || !bits[0] {
		t.Fatalf("bits mismatch: %#v", bits)
	}
}
