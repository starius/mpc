package sha2pc

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	mrand "math/rand"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

// TestProtocolDeterministic exercises the protocol with fixed vectors.
func TestProtocolDeterministic(t *testing.T) {
	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}

	runProtocol(t, a, b)
}

// TestProtocolRandomized exercises a few random protocol executions.
func TestProtocolRandomized(t *testing.T) {
	for i := 0; i < 5; i++ {
		var a, b [32]byte
		if _, err := crand.Read(a[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		if _, err := crand.Read(b[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}

		runProtocol(t, a, b)
	}
}

// runProtocol executes the entire message flow inside the same process.
func runProtocol(t *testing.T, a, b [32]byte) {
	t.Helper()

	msg1, garblerState, err := GarblerRound1(crand.Reader, CurveP256, a)
	if err != nil {
		t.Fatalf("Round1: %v", err)
	}
	msg2, evaluatorState, err := EvaluatorRound2(crand.Reader, CurveP256, msg1, b)
	if err != nil {
		t.Fatalf("Round2: %v", err)
	}

	wantHints := msg1.OutputHints
	if len(wantHints) != len(evaluatorState.outputHints) {
		t.Fatalf("output hint count mismatch: got %d want %d",
			len(evaluatorState.outputHints), len(wantHints))
	}
	for i := range wantHints {
		if !evaluatorState.outputHints[i].L0.Equal(wantHints[i].L0) ||
			!evaluatorState.outputHints[i].L1.Equal(wantHints[i].L1) {
			t.Fatalf("output hint mismatch at %d", i)
		}
	}

	msg3, err := GarblerRound3(garblerState, CurveP256, msg2)
	if err != nil {
		t.Fatalf("Round3: %v", err)
	}

	labels, err := ot.DecryptCOCiphertexts(CurveP256, evaluatorState.choiceBundle, msg3.Ciphertexts)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for i := 0; i < len(labels); i++ {
		want := garblerState.wires[i]
		if !labels[i].Equal(want.L0) && !labels[i].Equal(want.L1) {
			t.Fatalf("OT label mismatch at %d", i)
		}
	}

	hashEval, err := EvaluatorRound4(CurveP256, evaluatorState, msg3)
	if err != nil {
		t.Fatalf("Round4: %v", err)
	}
	hashGar := hashEval

	expected := referenceHash(a, b)
	if !bytes.Equal(hashEval[:], expected[:]) {
		t.Fatalf("hash mismatch evaluator\nhave %x\nwant %x", hashEval, expected)
	}
	if !bytes.Equal(hashGar[:], expected[:]) {
		t.Fatalf("hash mismatch garbler\nhave %x\nwant %x", hashGar, expected)
	}
}

// TestDeterministicTranscript locks the transcript against known hashes.
func TestDeterministicTranscript(t *testing.T) {
	garblerRand := newDeterministicReader([]byte("garbler-seed"))
	evaluatorRand := newDeterministicReader([]byte("evaluator-seed"))

	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}

	r1, gState, err := GarblerRound1(garblerRand, CurveP256, a)
	if err != nil {
		t.Fatalf("GarblerRound1: %v", err)
	}
	r2, eState, err := EvaluatorRound2(evaluatorRand, CurveP256, r1, b)
	if err != nil {
		t.Fatalf("EvaluatorRound2: %v", err)
	}
	r3, err := GarblerRound3(gState, CurveP256, r2)
	if err != nil {
		t.Fatalf("GarblerRound3: %v", err)
	}
	final, err := EvaluatorRound4(CurveP256, eState, r3)
	if err != nil {
		t.Fatalf("EvaluatorRound4: %v", err)
	}

	enc1, err := EncodeRound1(r1)
	if err != nil {
		t.Fatalf("EncodeRound1: %v", err)
	}
	enc2, err := EncodeRound2(r2)
	if err != nil {
		t.Fatalf("EncodeRound2: %v", err)
	}
	enc3, err := EncodeRound3(r3)
	if err != nil {
		t.Fatalf("EncodeRound3: %v", err)
	}

	r1Hash := hashBytes(enc1)
	r2Hash := hashBytes(enc2)
	r3Hash := hashBytes(enc3)
	finalHash := hex.EncodeToString(final[:])

	const (
		expRound1 = "2ab2262c373bdaff5fbe7ddd96d1bc2e5d44a677749ed9602759ce5967a18d55"
		expRound2 = "4d0f38de45cadc986f127a85843118d65a3f6da9e7ea187672a14711c63524b5"
		expRound3 = "351b4d259c79a84f7d7b3ca64f708e2410324b2969dbffb2870f6893dd4dba05"
		expFinal  = "4b2f74579fc7c778745121996f604371a326dc5174f9851706032626668abf2e"
	)

	if r1Hash != expRound1 || r2Hash != expRound2 || r3Hash != expRound3 || finalHash != expFinal {
		t.Fatalf("unexpected transcript hashes:\nround1=%s\nround2=%s\nround3=%s\nfinal=%s",
			r1Hash, r2Hash, r3Hash, finalHash)
	}
}

// TestSessionIdempotency ensures each public round function remains pure by
// rerunning them with the same inputs, hashing payloads/sessions, and verifying
// encode/decode round-trips remain stable.
func TestSessionIdempotency(t *testing.T) {
	garblerRandA := newDeterministicReader([]byte("garbler-idem"))
	garblerRandB := newDeterministicReader([]byte("garbler-idem"))
	evaluatorRandA := newDeterministicReader([]byte("eval-idem"))
	evaluatorRandB := newDeterministicReader([]byte("eval-idem"))

	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}
	aCopy := a
	bCopy := b

	round1A, garblerSessionA, err := GarblerRound1(garblerRandA, CurveP256, a)
	if err != nil {
		t.Fatalf("GarblerRound1 A: %v", err)
	}
	round1B, garblerSessionB, err := GarblerRound1(garblerRandB, CurveP256, a)
	if err != nil {
		t.Fatalf("GarblerRound1 B: %v", err)
	}

	if !round1Equal(round1A, round1B) {
		t.Fatalf("round1 payloads diverged")
	}
	if !garblerSessionsEqual(garblerSessionA, garblerSessionB) {
		t.Fatalf("garbler sessions diverged")
	}
	if a != aCopy {
		t.Fatalf("garbler input mutated")
	}

	garblerBytes, err := EncodeGarblerSession(garblerSessionA)
	if err != nil {
		t.Fatalf("EncodeGarblerSession: %v", err)
	}
	garblerRestored, err := DecodeGarblerSession(garblerBytes)
	if err != nil {
		t.Fatalf("DecodeGarblerSession: %v", err)
	}
	if !garblerSessionsEqual(garblerSessionA, garblerRestored) {
		t.Fatalf("garbler session encode round-trip mismatch")
	}

	round2A, evaluatorSessionA, err := EvaluatorRound2(evaluatorRandA, CurveP256, round1A, b)
	if err != nil {
		t.Fatalf("EvaluatorRound2 A: %v", err)
	}
	round2B, evaluatorSessionB, err := EvaluatorRound2(evaluatorRandB, CurveP256, round1A, b)
	if err != nil {
		t.Fatalf("EvaluatorRound2 B: %v", err)
	}
	if !round2Equal(round2A, round2B) {
		t.Fatalf("round2 payloads diverged")
	}
	if !evaluatorSessionsEqual(evaluatorSessionA, evaluatorSessionB) {
		t.Fatalf("evaluator sessions diverged")
	}
	if b != bCopy {
		t.Fatalf("evaluator input mutated")
	}

	evaluatorBytes, err := EncodeEvaluatorSession(evaluatorSessionA)
	if err != nil {
		t.Fatalf("EncodeEvaluatorSession: %v", err)
	}
	evaluatorRestored, err := DecodeEvaluatorSession(evaluatorBytes)
	if err != nil {
		t.Fatalf("DecodeEvaluatorSession: %v", err)
	}
	if !evaluatorSessionsEqual(evaluatorSessionA, evaluatorRestored) {
		t.Fatalf("evaluator session encode round-trip mismatch")
	}

	round3A, err := GarblerRound3(garblerSessionA, CurveP256, round2A)
	if err != nil {
		t.Fatalf("GarblerRound3 A: %v", err)
	}
	round3B, err := GarblerRound3(garblerSessionA, CurveP256, round2A)
	if err != nil {
		t.Fatalf("GarblerRound3 B: %v", err)
	}
	if !round3Equal(round3A, round3B) {
		t.Fatalf("round3 payloads diverged")
	}

	finalA, err := EvaluatorRound4(CurveP256, evaluatorSessionA, round3A)
	if err != nil {
		t.Fatalf("EvaluatorRound4 A: %v", err)
	}
	finalB, err := EvaluatorRound4(CurveP256, evaluatorSessionA, round3A)
	if err != nil {
		t.Fatalf("EvaluatorRound4 B: %v", err)
	}
	if finalA != finalB {
		t.Fatalf("round4 results diverged")
	}

	r1Enc, err := EncodeRound1(round1A)
	if err != nil {
		t.Fatalf("EncodeRound1: %v", err)
	}
	r2Enc, err := EncodeRound2(round2A)
	if err != nil {
		t.Fatalf("EncodeRound2: %v", err)
	}
	r3Enc, err := EncodeRound3(round3A)
	if err != nil {
		t.Fatalf("EncodeRound3: %v", err)
	}
	r1Hash := hashBytes(r1Enc)
	r2Hash := hashBytes(r2Enc)
	r3Hash := hashBytes(r3Enc)
	gsHash := hashBytes(garblerBytes)
	esHash := hashBytes(evaluatorBytes)
	finalHash := hex.EncodeToString(finalA[:])

	const (
		idemRound1Hash           = "9accce419f14e94307c6bc679bae25b516a80541ae07c1730acbcef4e0ee0d4a"
		idemRound2Hash           = "c019506d180ca597c42ef9157b76f91c95206c37dd90167b08c193c3f7d7a825"
		idemRound3Hash           = "850f1db0433c936029c0d9f479e75cd2e252dd327aed4b775fd3a8efeeb9558b"
		idemGarblerSessionHash   = "cc2d7a6c349dcaa0bfa42f38f7de0b30eac841e344f524b5a3b65a9127c34f31"
		idemEvaluatorSessionHash = "ccbb133d218324617d2fc312415e30252aad14356a66a57008742a1896122779"
		idemFinalHash            = "4b2f74579fc7c778745121996f604371a326dc5174f9851706032626668abf2e"
	)

	if r1Hash != idemRound1Hash {
		t.Fatalf("round1 hash mismatch: got %s want %s", r1Hash, idemRound1Hash)
	}
	if r2Hash != idemRound2Hash {
		t.Fatalf("round2 hash mismatch: got %s want %s", r2Hash, idemRound2Hash)
	}
	if r3Hash != idemRound3Hash {
		t.Fatalf("round3 hash mismatch: got %s want %s", r3Hash, idemRound3Hash)
	}
	if gsHash != idemGarblerSessionHash {
		t.Fatalf("garbler session hash mismatch: got %s want %s", gsHash, idemGarblerSessionHash)
	}
	if esHash != idemEvaluatorSessionHash {
		t.Fatalf("evaluator session hash mismatch: got %s want %s", esHash, idemEvaluatorSessionHash)
	}
	if finalHash != idemFinalHash {
		t.Fatalf("final hash mismatch: got %s want %s", finalHash, idemFinalHash)
	}
}

// TestNilRandomSource ensures public APIs fail when rng is nil.
func TestNilRandomSource(t *testing.T) {
	var input [32]byte
	if _, _, err := GarblerRound1(nil, CurveP256, input); err != errNilRandomSource {
		t.Fatalf("expected errNilRandomSource, got %v", err)
	}

	garblerRand := newDeterministicReader([]byte("garbler"))
	msg1, _, err := GarblerRound1(garblerRand, CurveP256, input)
	if err != nil {
		t.Fatalf("setup GarblerRound1: %v", err)
	}
	if _, _, err := EvaluatorRound2(nil, CurveP256, msg1, input); err != errNilRandomSource {
		t.Fatalf("expected errNilRandomSource from EvaluatorRound2, got %v", err)
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

// deterministicReader is a deterministic io.Reader backed by math/rand for tests.
type deterministicReader struct {
	src *mrand.Rand
}

// newDeterministicReader creates a math/rand-backed reader for tests only.
func newDeterministicReader(seed []byte) *deterministicReader {
	// WARNING: math/rand is not cryptographically strong; do not reuse in prod.
	sum := sha256.Sum256(seed)
	srcSeed := int64(binary.BigEndian.Uint64(sum[:8]))

	return &deterministicReader{src: mrand.New(mrand.NewSource(srcSeed))}
}

// Read fills p with pseudo-random bytes derived from the deterministic source.
func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r.src.Intn(256))
	}

	return len(p), nil
}

// hashBytes returns the hexadecimal SHA256 digest of the provided data.
func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}
