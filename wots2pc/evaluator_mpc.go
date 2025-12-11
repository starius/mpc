package wots2pc

import (
	"crypto/elliptic"
	"fmt"
	"io"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

// EvaluatorRound2 prepares OT choices for the evaluator's sk_seed share.
func EvaluatorRound2(rng io.Reader, curve elliptic.Curve, msg Round1Payload, skSeedE [32]byte) (Round2Payload, *EvaluatorSession, error) {
	if rng == nil {
		return Round2Payload{}, nil, errNilRandomSource
	}
	if curve == nil {
		return Round2Payload{}, nil, errNilCurve
	}
	circ := wotsChainCircuit
	if circ.NumParties() != 2 {
		return Round2Payload{}, nil, fmt.Errorf("expected 2-party circuit, got %d", circ.NumParties())
	}
	if msg.OT.CurveName != curve.Params().Name {
		return Round2Payload{}, nil, fmt.Errorf("curve mismatch: %s vs %s", msg.OT.CurveName, curve.Params().Name)
	}

	state := &EvaluatorSession{SessionID: msg.SessionID}
	bits := bytesToBitsLittle(skSeedE[:])
	if len(bits) != evaluatorBitCount {
		return Round2Payload{}, nil, fmt.Errorf("evaluator input mismatch: got %d bits want %d", len(bits), evaluatorBitCount)
	}
	bundle, choices, err := ot.BuildCOChoices(rng, curve, msg.OT.A.X, msg.OT.A.Y, bits)
	if err != nil {
		return Round2Payload{}, nil, err
	}
	state.ChoiceBundle = bundle

	return Round2Payload{
		SessionID: msg.SessionID,
		CurveName: curve.Params().Name,
		Choices:   choices,
	}, state, nil
}

// EvaluatorRound4 evaluates all chains and returns the WOTS+ public key.
func EvaluatorRound4(curve elliptic.Curve, state *EvaluatorSession, msg Round3Payload, pubSeed [32]byte, baseAddr Address) ([]byte, error) {
	if state == nil || len(state.ChoiceBundle.Scalars) == 0 {
		return nil, fmt.Errorf("invalid evaluator state for round 4")
	}
	if curve == nil {
		return nil, errNilCurve
	}
	if msg.SessionID != state.SessionID {
		return nil, fmt.Errorf("session id mismatch: got %d want %d", msg.SessionID, state.SessionID)
	}

	evalLabels, err := ot.DecryptCOCiphertexts(curve, state.ChoiceBundle, msg.Ciphertexts)
	if err != nil {
		return nil, err
	}
	if len(msg.GarblerInputs) != garblerSecretBits {
		return nil, fmt.Errorf("garbler input label mismatch: got %d want %d", len(msg.GarblerInputs), garblerSecretBits)
	}
	if len(msg.PublicInputs) != publicBitCount {
		return nil, fmt.Errorf("public label mismatch: got %d want %d", len(msg.PublicInputs), publicBitCount)
	}

	pubSeedBits := bytesToBitsLittle(pubSeed[:])
	pk := make([]byte, SHA2_256sParams.Len*SHA2_256sParams.N)

	for chainIdx := 0; chainIdx < SHA2_256sParams.Len; chainIdx++ {
		addr := baseAddr
		addr.SetChain(byte(chainIdx))

		// Assemble input wires: skG labels, pub labels chosen per bit, evaluator labels.
		wires := make([]ot.Label, totalWires)
		copy(wires[:garblerSecretBits], msg.GarblerInputs)

		pubBits := make([]bool, publicBitCount)
		addrBits := bytesToBitsLittle(addr[:])
		copy(pubBits[:256], pubSeedBits)
		copy(pubBits[256:], addrBits)
		for i := 0; i < publicBitCount; i++ {
			w := msg.PublicInputs[i]
			if pubBits[i] {
				wires[garblerSecretBits+i] = w.L1
			} else {
				wires[garblerSecretBits+i] = w.L0
			}
		}

		copy(wires[garblerInputBitCount:], evalLabels)

		if err := wotsChainCircuit.Eval(msg.Key[:], wires, msg.GarbledTables); err != nil {
			return nil, err
		}

		if len(msg.OutputHints) != outputHintCount {
			return nil, fmt.Errorf("output hint mismatch: have %d want %d", len(msg.OutputHints), outputHintCount)
		}
		start := wotsChainCircuit.NumWires - len(msg.OutputHints)
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
