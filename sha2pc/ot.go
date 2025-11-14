package sha2pc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"

	"github.com/markkurossi/mpc/ot"
)

// ecPoint stores affine coordinates used in OT.
type ecPoint struct {
	// x holds the affine x coordinate.
	x *big.Int
	// y holds the affine y coordinate.
	y *big.Int
}

// otSenderState tracks the sender's Chou-Orlandi session.
type otSenderState struct {
	// curve holds the elliptic curve in use.
	curve elliptic.Curve

	// hash stores the KDF hash function.
	hash hash.Hash

	// a is the sender's scalar.
	a *big.Int

	// Ax, Ay form the public point A = g^a.
	Ax, Ay *big.Int

	// AaInvx is the x coordinate of A^{-a}.
	AaInvx *big.Int

	// AaInvy is the y coordinate of A^{-a}.
	AaInvy *big.Int

	// wires lists the wire labels to protect with OT.
	wires []ot.Wire
}

// newOTSenderState creates a sender OT state for the provided wires.
func newOTSenderState(curve elliptic.Curve, wires []ot.Wire) (*otSenderState, error) {
	params := curve.Params()
	a, err := rand.Int(rand.Reader, params.N)
	if err != nil {
		return nil, err
	}
	Ax, Ay := curve.ScalarBaseMult(a.Bytes())
	Aax, Aay := curve.ScalarMult(Ax, Ay, a.Bytes())

	AaInvx := big.NewInt(0).Set(Aax)
	AaInvy := big.NewInt(0).Sub(params.P, Aay)

	return &otSenderState{
		curve:  curve,
		hash:   sha256.New(),
		a:      a,
		Ax:     Ax,
		Ay:     Ay,
		AaInvx: AaInvx,
		AaInvy: AaInvy,
		wires:  wires,
	}, nil
}

// encrypt produces OT ciphertext pairs for the provided receiver points.
func (s *otSenderState) encrypt(points []ecPoint) ([]byte, error) {
	if len(points) != len(s.wires) {
		return nil, fmt.Errorf("OT point count mismatch: got %d want %d",
			len(points), len(s.wires))
	}
	var buf bytes.Buffer
	var tmp ot.LabelData
	for idx, point := range points {
		id := uint64(idx)
		Bx, By := s.curve.ScalarMult(point.x, point.y, s.a.Bytes())
		Bax, Bay := s.curve.Add(Bx, By, s.AaInvx, s.AaInvy)

		mask0 := kdf(s.hash, Bx, By, id)
		mask1 := kdf(s.hash, Bax, Bay, id)

		s.wires[idx].L0.GetData(&tmp)
		e0 := xor(mask0, tmp[:])
		buf.Write(e0)

		s.wires[idx].L1.GetData(&tmp)
		e1 := xor(mask1, tmp[:])
		buf.Write(e1)
	}
	return buf.Bytes(), nil
}

// otReceiverState tracks the receiver's Chou-Orlandi session.
type otReceiverState struct {
	// curve holds the elliptic curve in use.
	curve elliptic.Curve

	// hash stores the KDF hash function.
	hash hash.Hash

	// Ax, Ay form the sender's public point A.
	Ax, Ay *big.Int

	// choices stores the receiver's selection bits.
	choices []bool

	// bVals keeps the receiver's random scalars.
	bVals []*big.Int
}

// newOTReceiverState creates a receiver OT state for the given inputs.
func newOTReceiverState(curve elliptic.Curve, Ax, Ay *big.Int, choiceCount int) *otReceiverState {
	return &otReceiverState{
		curve:   curve,
		hash:    sha256.New(),
		Ax:      Ax,
		Ay:      Ay,
		choices: make([]bool, choiceCount),
		bVals:   make([]*big.Int, choiceCount),
	}
}

// buildChoice prepares the EC point corresponding to a desired bit.
func (r *otReceiverState) buildChoice(idx int, bit bool) (ecPoint, error) {
	params := r.curve.Params()
	b, err := rand.Int(rand.Reader, params.N)
	if err != nil {
		return ecPoint{}, err
	}
	Bx, By := r.curve.ScalarBaseMult(b.Bytes())
	if bit {
		Bx, By = r.curve.Add(Bx, By, r.Ax, r.Ay)
	}
	r.choices[idx] = bit
	r.bVals[idx] = b
	return ecPoint{
		x: Bx,
		y: By,
	}, nil
}

// decrypt converts OT ciphertext pairs back into the requested labels.
func (r *otReceiverState) decrypt(data []byte) ([]ot.Label, error) {
	if len(data)%32 != 0 {
		return nil, fmt.Errorf("invalid OT ciphertext block")
	}
	count := len(r.choices)
	if len(data) != count*32 {
		return nil, fmt.Errorf("OT ciphertext length mismatch")
	}
	result := make([]ot.Label, count)
	var tmp ot.LabelData
	for idx := 0; idx < count; idx++ {
		id := uint64(idx)
		bytes := r.bVals[idx].Bytes()
		Asx, Asy := r.curve.ScalarMult(r.Ax, r.Ay, bytes)

		dataMask := kdf(r.hash, Asx, Asy, id)

		var cipher []byte
		if r.choices[idx] {
			offset := idx*32 + 16
			cipher = data[offset : offset+16]
		} else {
			offset := idx * 32
			cipher = data[offset : offset+16]
		}
		dataMask = xor(dataMask, cipher)
		copy(tmp[:], dataMask[:16])
		result[idx].SetData(&tmp)
	}
	return result, nil
}

// kdf derives XOR pads from the EC Diffie-Hellman secret.
func kdf(hash hash.Hash, x, y *big.Int, id uint64) []byte {
	hash.Reset()
	hash.Write(x.Bytes())
	hash.Write(y.Bytes())

	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], id)
	hash.Write(tmp[:])

	return hash.Sum(nil)
}

// xor applies XOR in place (dst ^= src) and returns dst.
func xor(dst, src []byte) []byte {
	l := len(dst)
	if len(src) < l {
		l = len(src)
	}
	for i := 0; i < l; i++ {
		dst[i] ^= src[i]
	}
	return dst[:l]
}
