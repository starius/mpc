package wots2pc

import (
	"crypto/elliptic"
	"fmt"
	"io"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

// EvaluatorRound2 prepares OT choices for the evaluator's sk_seed share and validates public data/meta.
func EvaluatorRound2(rng io.Reader, curve elliptic.Curve, msg Round1Payload, public PublicData, meta CircuitMeta, skSeedE [32]byte) (Round2Payload, *EvaluatorSession, error) {
	if rng == nil {
		return Round2Payload{}, nil, errNilRandomSource
	}
	if curve == nil {
		return Round2Payload{}, nil, errNilCurve
	}
	if msg.OT.CurveName != curve.Params().Name {
		return Round2Payload{}, nil, fmt.Errorf("curve mismatch: %s vs %s", msg.OT.CurveName, curve.Params().Name)
	}
	if msg.Public != public {
		return Round2Payload{}, nil, fmt.Errorf("public data mismatch")
	}
	if msg.Meta != meta {
		return Round2Payload{}, nil, fmt.Errorf("circuit meta mismatch")
	}

	state := &EvaluatorSession{SessionID: msg.SessionID}
	bits := bytesToBitsLittle(skSeedE[:])
	bundle, choices, err := ot.BuildCOChoices(rng, curve, msg.OT.A.X, msg.OT.A.Y, bits)
	if err != nil {
		return Round2Payload{}, nil, err
	}
	state.ChoiceBundle = bundle

	return Round2Payload{
		SessionID: msg.SessionID,
		CurveName: curve.Params().Name,
		Choices:   choices,
		Public:    public,
		Meta:      meta,
	}, state, nil
}

// EvaluatorRound4 evaluates all chains and returns the WOTS+ public key.
func EvaluatorRound4(curve elliptic.Curve, circ *circuit.Circuit, public PublicData, meta CircuitMeta, state *EvaluatorSession, msg Round3Payload) ([]byte, error) {
	if state == nil || len(state.ChoiceBundle.Scalars) == 0 {
		return nil, fmt.Errorf("invalid evaluator state for round 4")
	}
	if curve == nil {
		return nil, errNilCurve
	}
	if circ == nil {
		return nil, fmt.Errorf("nil circuit")
	}
	if msg.SessionID != state.SessionID {
		return nil, fmt.Errorf("session id mismatch: got %d want %d", msg.SessionID, state.SessionID)
	}
	if msg.Public != public {
		return nil, fmt.Errorf("public data mismatch")
	}
	if msg.Meta != meta {
		return nil, fmt.Errorf("circuit meta mismatch")
	}

	info, err := deriveInfo(circ)
	if err != nil {
		return nil, err
	}

	evalLabels, err := ot.DecryptCOCiphertexts(curve, state.ChoiceBundle, msg.Ciphertexts)
	if err != nil {
		return nil, err
	}
	const secretBits = 256
	if info.GarblerBits < secretBits {
		return nil, fmt.Errorf("garbler bits %d too small", info.GarblerBits)
	}
	publicBits := info.GarblerBits - secretBits
	if len(msg.GarblerInputs) != secretBits {
		return nil, fmt.Errorf("garbler input label mismatch: got %d want %d", len(msg.GarblerInputs), secretBits)
	}
	if len(msg.PublicInputs) != publicBits {
		return nil, fmt.Errorf("public input label mismatch: got %d want %d", len(msg.PublicInputs), publicBits)
	}

	pk := make([]byte, SHA2_256sParams.Len*SHA2_256sParams.N)

	for chainIdx := 0; chainIdx < SHA2_256sParams.Len; chainIdx++ {
		chain := byte(chainIdx)
		wires := make([]ot.Label, info.TotalWires)
		copy(wires[:secretBits], msg.GarblerInputs)

		// public bits encode chain (little-endian bits).
		for i := 0; i < publicBits; i++ {
			w := msg.PublicInputs[i]
			if ((chain >> uint(i)) & 1) == 1 {
				wires[secretBits+i] = w.L1
			} else {
				wires[secretBits+i] = w.L0
			}
		}

		copy(wires[info.GarblerBits:], evalLabels)

		if err := circ.Eval(msg.Key[:], wires, msg.GarbledTables); err != nil {
			return nil, err
		}

		if len(msg.OutputHints) != info.OutputBits {
			return nil, fmt.Errorf("output hint mismatch: have %d want %d", len(msg.OutputHints), info.OutputBits)
		}
		start := circ.NumWires - len(msg.OutputHints)
		outputBits := make([]bool, len(msg.OutputHints))
		for i := 0; i < len(msg.OutputHints); i++ {
			bit, err := circuit.BitFromLabel(msg.OutputHints[i], wires[int(start)+i])
			if err != nil {
				return nil, err
			}
			outputBits[i] = bit
		}
		bytes := bitsToBytesLittle(outputBits)
		copy(pk[chainIdx*SHA2_256sParams.N:(chainIdx+1)*SHA2_256sParams.N], bytes)
	}
	return pk, nil
}
