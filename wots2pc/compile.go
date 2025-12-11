package wots2pc

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/markkurossi/mpc/circuit"
)

// PublicData bundles the public parameters that get hardcoded into the circuit.
type PublicData struct {
	PubSeed [32]byte
	Addr    Address
}

// CircuitMeta captures identifying metadata to catch mismatches.
type CircuitMeta struct {
	Gates int
	Wires int
	Hash  [32]byte
}

// CompileCircuit hardcodes pubSeed and base address into the chain circuit,
// compiles it, and returns the parsed circuit plus metadata.
func CompileCircuit(public PublicData) (*circuit.Circuit, CircuitMeta, error) {
	src := renderChain(public)
	tmpDir, err := os.MkdirTemp("", "wots-chain-*")
	if err != nil {
		return nil, CircuitMeta{}, err
	}
	defer os.RemoveAll(tmpDir)

	mpclPath := filepath.Join(tmpDir, "wots_chain.mpcl")
	if err := os.WriteFile(mpclPath, []byte(src), 0644); err != nil {
		return nil, CircuitMeta{}, err
	}
	outPath := mpclPath + "c"

	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), ".."))
	cmd := exec.Command("go", "run", filepath.Join(repoRoot, "apps", "garbled"), "-circ", "-format", "mpclc", "-O", "1", mpclPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "MPCLDIR="+repoRoot)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, CircuitMeta{}, fmt.Errorf("compile circuit: %v: %s", err, out)
	}
	mpclc, err := os.ReadFile(outPath)
	if err != nil {
		return nil, CircuitMeta{}, err
	}
	circ, err := circuit.ParseMPCLC(bytes.NewReader(mpclc))
	if err != nil {
		return nil, CircuitMeta{}, err
	}
	var meta CircuitMeta
	meta.Gates = len(circ.Gates)
	meta.Wires = int(circ.NumWires)
	meta.Hash = sha256.Sum256(mpclc)
	return circ, meta, nil
}

func renderChain(public PublicData) string {
	return fmt.Sprintf(wotsChainTemplate, literal32(public.PubSeed), literal32(public.Addr))
}

func literal32(data [32]byte) string {
	var b bytes.Buffer
	b.WriteString("[32]byte{")
	for i, v := range data {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "0x%02x", v)
	}
	b.WriteString("}")
	return b.String()
}
