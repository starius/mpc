package sha2pc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// TestProtocolDeterministic exercises the protocol with fixed vectors.
func TestProtocolDeterministic(t *testing.T) {
	cfg := &Config{}
	garbler, err := NewGarbler(cfg)
	if err != nil {
		t.Fatalf("NewGarbler: %v", err)
	}
	evaluator, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}

	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}

	runProtocol(t, garbler, evaluator, a, b)
}

// TestProtocolRandomized exercises a few random protocol executions.
func TestProtocolRandomized(t *testing.T) {
	cfg := &Config{}
	for i := 0; i < 5; i++ {
		garbler, err := NewGarbler(cfg)
		if err != nil {
			t.Fatalf("NewGarbler: %v", err)
		}
		evaluator, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatalf("NewEvaluator: %v", err)
		}

		var a, b [32]byte
		if _, err := rand.Read(a[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}

		runProtocol(t, garbler, evaluator, a, b)
	}
}

// runProtocol executes the entire message flow inside the same process.
func runProtocol(t *testing.T, garbler *Garbler, evaluator *Evaluator, a, b [32]byte) {
	t.Helper()

	msg1, err := garbler.Round1(a)
	if err != nil {
		t.Fatalf("Round1: %v", err)
	}
	msg2, err := evaluator.Round2(msg1, b)
	if err != nil {
		t.Fatalf("Round2: %v", err)
	}

	wantHints := selectOutputWires(garbler.circ, garbler.garbled)
	if len(wantHints) != len(evaluator.outputHints) {
		t.Fatalf("output hint count mismatch: got %d want %d",
			len(evaluator.outputHints), len(wantHints))
	}
	for i := range wantHints {
		if !evaluator.outputHints[i].L0.Equal(wantHints[i].L0) ||
			!evaluator.outputHints[i].L1.Equal(wantHints[i].L1) {
			t.Fatalf("output hint mismatch at %d", i)
		}
	}
	msg3, err := garbler.Round3(msg2)
	if err != nil {
		t.Fatalf("Round3: %v", err)
	}

	payload, err := parseMessage(msg3, round3Kind)
	if err != nil {
		t.Fatalf("parse Round3: %v", err)
	}
	reader := newChunkReader(payload)
	cipherData, err := reader.readChunk()
	if err != nil {
		t.Fatalf("cipher chunk: %v", err)
	}
	labels, err := evaluator.receiver.decrypt(cipherData)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for i := 0; i < len(labels); i++ {
		want := garbler.garbled.Wires[garbler.garblerBits+i]
		if !labels[i].Equal(want.L0) && !labels[i].Equal(want.L1) {
			t.Fatalf("OT label mismatch at %d", i)
		}
	}
	hashEval, msg4, err := evaluator.Round4(msg3)
	if err != nil {
		t.Fatalf("Round4: %v", err)
	}
	hashGar, err := garbler.Finalize(msg4)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	expected := referenceHash(a, b)
	if !bytes.Equal(hashEval[:], expected[:]) {
		t.Fatalf("hash mismatch evaluator\nhave %x\nwant %x", hashEval, expected)
	}
	if !bytes.Equal(hashGar[:], expected[:]) {
		t.Fatalf("hash mismatch garbler\nhave %x\nwant %x", hashGar, expected)
	}
}

// referenceHash computes sha256(xor(a,b)) locally for validation.
func referenceHash(a, b [32]byte) [32]byte {
	var tmp [32]byte
	for i := 0; i < len(tmp); i++ {
		tmp[i] = a[i] ^ b[i]
	}
	return sha256.Sum256(tmp[:])
}
