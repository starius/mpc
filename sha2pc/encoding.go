package sha2pc

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/ot"
)

const (
	// magicRound1 tags Round1 payload encodings.
	magicRound1 = "R1"

	// magicRound2 tags Round2 payload encodings.
	magicRound2 = "R2"

	// magicRound3 tags Round3 payload encodings.
	magicRound3 = "R3"

	// magicGarblerSession tags garbler session encodings.
	magicGarblerSession = "GS"

	// magicEvalSession tags evaluator session encodings.
	magicEvalSession = "ES"
)

var byteOrder = binary.BigEndian

// EncodeRound1 turns a Round1Payload into bytes.
func EncodeRound1(p Round1Payload) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte(magicRound1))
	writeChunk(&buf, encodeOTSetup(p.OT))

	return buf.Bytes(), nil
}

// DecodeRound1 reconstructs a Round1Payload from bytes.
func DecodeRound1(data []byte) (Round1Payload, error) {
	reader := bytes.NewReader(data)
	var payload Round1Payload
	magic := make([]byte, 2)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return Round1Payload{}, err
	}
	if string(magic) != magicRound1 {
		return Round1Payload{}, fmt.Errorf("invalid round1 magic")
	}
	chunk, err := readChunk(reader)
	if err != nil {
		return Round1Payload{}, err
	}
	payload.OT, err = decodeOTSetup(chunk)
	if err != nil {
		return Round1Payload{}, err
	}

	return payload, nil
}

// EncodeRound2 turns a Round2Payload into bytes.
func EncodeRound2(p Round2Payload) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte(magicRound2))
	buf.Write(encodePoints(p.Choices))

	return buf.Bytes(), nil
}

// DecodeRound2 reconstructs a Round2Payload.
func DecodeRound2(data []byte) (Round2Payload, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, 2)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return Round2Payload{}, err
	}
	if string(magic) != magicRound2 {
		return Round2Payload{}, fmt.Errorf("invalid round2 magic")
	}

	rest, err := io.ReadAll(reader)
	if err != nil {
		return Round2Payload{}, err
	}

	points, err := decodePoints(rest)
	if err != nil {
		return Round2Payload{}, err
	}

	return Round2Payload{Choices: points}, nil
}

// EncodeRound3 turns a Round3Payload into bytes.
func EncodeRound3(p Round3Payload) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte(magicRound3))
	buf.Write(p.Key[:])
	writeChunk(&buf, encodeGarbledTables(p.GarbledTables))
	writeChunk(&buf, encodeLabels(p.GarblerInputs))
	writeChunk(&buf, encodeOutputHints(p.OutputHints))
	writeChunk(&buf, encodeCiphertexts(p.Ciphertexts))

	return buf.Bytes(), nil
}

// DecodeRound3 reconstructs a Round3Payload from bytes.
func DecodeRound3(data []byte) (Round3Payload, error) {
	reader := bytes.NewReader(data)
	var payload Round3Payload
	magic := make([]byte, 2)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return Round3Payload{}, err
	}
	if string(magic) != magicRound3 {
		return Round3Payload{}, fmt.Errorf("invalid round3 magic")
	}
	if _, err := io.ReadFull(reader, payload.Key[:]); err != nil {
		return Round3Payload{}, err
	}
	chunk, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.GarbledTables, err = decodeGarbledTables(chunk)
	if err != nil {
		return Round3Payload{}, err
	}
	chunk, err = readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.GarblerInputs, err = decodeLabels(chunk)
	if err != nil {
		return Round3Payload{}, err
	}
	chunk, err = readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.OutputHints, err = decodeOutputHints(chunk)
	if err != nil {
		return Round3Payload{}, err
	}
	chunk, err = readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.Ciphertexts, err = decodeCiphertexts(chunk)
	if err != nil {
		return Round3Payload{}, err
	}

	return payload, nil
}

// EncodeGarblerSession serializes a GarblerSession for persistence.
func EncodeGarblerSession(session *GarblerSession) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("nil garbler session")
	}

	var buf bytes.Buffer
	buf.Write([]byte(magicGarblerSession))
	writeChunk(&buf, encodeCOSenderSetup(session.senderSetup))

	return buf.Bytes(), nil
}

// DecodeGarblerSession reconstructs a GarblerSession from bytes.
func DecodeGarblerSession(data []byte) (*GarblerSession, error) {
	reader := bytes.NewReader(data)
	var session GarblerSession
	magic := make([]byte, 2)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, err
	}
	if string(magic) != magicGarblerSession {
		return nil, fmt.Errorf("invalid garbler session magic")
	}

	chunk, err := readChunk(reader)
	if err != nil {
		return nil, err
	}
	session.senderSetup, err = decodeCOSenderSetup(chunk)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// EncodeEvaluatorSession serializes an EvaluatorSession for persistence.
func EncodeEvaluatorSession(session *EvaluatorSession) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("nil evaluator session")
	}

	var buf bytes.Buffer
	buf.Write([]byte(magicEvalSession))
	writeChunk(&buf, encodeChoiceBundle(session.choiceBundle))

	return buf.Bytes(), nil
}

// DecodeEvaluatorSession reconstructs an EvaluatorSession from bytes.

func DecodeEvaluatorSession(data []byte) (*EvaluatorSession, error) {
	reader := bytes.NewReader(data)
	var session EvaluatorSession
	magic := make([]byte, 2)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, err
	}
	if string(magic) != magicEvalSession {
		return nil, fmt.Errorf("invalid evaluator session magic")
	}

	chunk, err := readChunk(reader)
	if err != nil {
		return nil, err
	}
	session.choiceBundle, err = decodeChoiceBundle(chunk)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// encodeLabels flattens all labels into raw bytes.
func encodeLabels(labels []ot.Label) []byte {
	var buf bytes.Buffer
	var tmp ot.LabelData
	for _, l := range labels {
		l.GetData(&tmp)
		buf.Write(tmp[:])
	}

	return buf.Bytes()
}

// decodeLabels rebuilds labels from their byte form.
func decodeLabels(data []byte) ([]ot.Label, error) {
	const labelSize = 16
	if len(data)%labelSize != 0 {
		return nil, fmt.Errorf("label buffer misaligned")
	}
	var tmp ot.LabelData
	count := len(data) / labelSize
	result := make([]ot.Label, count)
	for i := 0; i < count; i++ {
		copy(tmp[:], data[i*labelSize:(i+1)*labelSize])
		result[i].SetData(&tmp)
	}

	return result, nil
}

// encodeGarbledTables serializes garbled table rows.
func encodeGarbledTables(tables [][]ot.Label) []byte {
	var buf bytes.Buffer
	var header [4]byte
	byteOrder.PutUint32(header[:], uint32(len(tables)))
	buf.Write(header[:])
	for _, row := range tables {
		byteOrder.PutUint32(header[:], uint32(len(row)))
		buf.Write(header[:])
		for _, label := range row {
			var tmp ot.LabelData
			label.GetData(&tmp)
			buf.Write(tmp[:])
		}
	}

	return buf.Bytes()
}

// decodeGarbledTables reconstructs table rows from bytes.
func decodeGarbledTables(data []byte) ([][]ot.Label, error) {
	reader := bytes.NewReader(data)
	var header [4]byte
	if _, err := reader.Read(header[:]); err != nil {
		return nil, err
	}
	count := int(byteOrder.Uint32(header[:]))
	result := make([][]ot.Label, count)
	var tmp ot.LabelData
	for i := 0; i < count; i++ {
		if _, err := reader.Read(header[:]); err != nil {
			return nil, err
		}
		rowLen := int(byteOrder.Uint32(header[:]))
		row := make([]ot.Label, rowLen)
		for j := 0; j < rowLen; j++ {
			if _, err := reader.Read(tmp[:]); err != nil {
				return nil, err
			}
			row[j].SetData(&tmp)
		}
		result[i] = row
	}

	return result, nil
}

// encodeOutputHints serializes every output wire.
func encodeOutputHints(wires []ot.Wire) []byte {
	var buf bytes.Buffer
	var tmp ot.LabelData
	var header [4]byte
	byteOrder.PutUint32(header[:], uint32(len(wires)))
	buf.Write(header[:])
	for _, wire := range wires {
		wire.L0.GetData(&tmp)
		buf.Write(tmp[:])
		wire.L1.GetData(&tmp)
		buf.Write(tmp[:])
	}

	return buf.Bytes()
}

// decodeOutputHints rebuilds output wires.
func decodeOutputHints(data []byte) ([]ot.Wire, error) {
	reader := bytes.NewReader(data)
	var header [4]byte
	if _, err := reader.Read(header[:]); err != nil {
		return nil, err
	}
	count := int(byteOrder.Uint32(header[:]))
	result := make([]ot.Wire, count)
	var tmp ot.LabelData
	for i := 0; i < count; i++ {
		if _, err := reader.Read(tmp[:]); err != nil {
			return nil, err
		}
		result[i].L0.SetData(&tmp)
		if _, err := reader.Read(tmp[:]); err != nil {
			return nil, err
		}
		result[i].L1.SetData(&tmp)
	}

	return result, nil
}

// encodePoints serializes EC points, storing each X coordinate and a packed set
// of Y parities to exploit standard compressed-point encoding.
func encodePoints(points []ot.ECPoint) []byte {
	var buf bytes.Buffer
	var header [4]byte
	byteOrder.PutUint32(header[:], uint32(len(points)))
	buf.Write(header[:])
	for _, p := range points {
		writeBigInt(&buf, p.X)
	}

	signs := packPointSigns(points)
	writeChunk(&buf, signs)

	return buf.Bytes()
}

// decodePoints rebuilds EC points from compressed X coordinates and sign bits.
func decodePoints(data []byte) ([]ot.ECPoint, error) {
	reader := bytes.NewReader(data)
	var header [4]byte
	if _, err := reader.Read(header[:]); err != nil {
		return nil, err
	}
	count := int(byteOrder.Uint32(header[:]))
	xs := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		x, err := readBigInt(reader)
		if err != nil {
			return nil, err
		}
		xs[i] = x
	}
	signs, err := readChunk(reader)
	if err != nil {
		return nil, err
	}
	if len(signs)*8 < count {
		return nil, fmt.Errorf("round2 sign buffer too short: have %d bits need %d", len(signs)*8, count)
	}
	if CurveP256 == nil {
		return nil, errNilCurve
	}
	byteLen := (CurveP256.Params().BitSize + 7) / 8
	result := make([]ot.ECPoint, count)
	for i := 0; i < count; i++ {
		odd := pointSign(signs, i)
		compressed := make([]byte, 1+byteLen)
		if odd {
			compressed[0] = 0x03
		} else {
			compressed[0] = 0x02
		}
		xBytes := xs[i].Bytes()
		copy(compressed[1+byteLen-len(xBytes):], xBytes)

		x, y := elliptic.UnmarshalCompressed(CurveP256, compressed)
		if x == nil || y == nil {
			return nil, fmt.Errorf("failed to decompress evaluator choice %d", i)
		}
		result[i] = ot.ECPoint{X: x, Y: y}
	}

	return result, nil
}

// packPointSigns packs the parity of the Y coordinate for each point.
func packPointSigns(points []ot.ECPoint) []byte {
	if len(points) == 0 {
		return nil
	}
	signs := make([]byte, (len(points)+7)/8)
	for i, p := range points {
		if p.Y.Bit(0) == 1 {
			signs[i/8] |= 1 << uint(i%8)
		}
	}

	return signs
}

// pointSign fetches the stored parity bit for the ith point.
func pointSign(signs []byte, idx int) bool {
	if len(signs) == 0 {
		return false
	}

	b := signs[idx/8]
	return (b & (1 << uint(idx%8))) != 0
}

// encodeCiphertexts serializes OT ciphertexts.
func encodeCiphertexts(ct []ot.LabelCiphertext) []byte {
	var buf bytes.Buffer
	var header [4]byte
	byteOrder.PutUint32(header[:], uint32(len(ct)))
	buf.Write(header[:])
	for _, c := range ct {
		buf.Write(c.Zero[:])
		buf.Write(c.One[:])
	}

	return buf.Bytes()
}

// decodeCiphertexts rebuilds OT ciphertexts.
func decodeCiphertexts(data []byte) ([]ot.LabelCiphertext, error) {
	reader := bytes.NewReader(data)
	var header [4]byte
	if _, err := reader.Read(header[:]); err != nil {
		return nil, err
	}
	count := int(byteOrder.Uint32(header[:]))
	result := make([]ot.LabelCiphertext, count)
	for i := 0; i < count; i++ {
		if _, err := reader.Read(result[i].Zero[:]); err != nil {
			return nil, err
		}
		if _, err := reader.Read(result[i].One[:]); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// encodeOTSetup serializes the OT sender setup.
func encodeOTSetup(otSetup OTSenderSetup) []byte {
	var buf bytes.Buffer
	writeChunk(&buf, []byte(otSetup.CurveName))
	writeBigInt(&buf, otSetup.A.X)
	writeBigInt(&buf, otSetup.A.Y)

	return buf.Bytes()
}

// decodeOTSetup rebuilds the OT sender setup.
func decodeOTSetup(data []byte) (OTSenderSetup, error) {
	reader := bytes.NewReader(data)
	name, err := readChunk(reader)
	if err != nil {
		return OTSenderSetup{}, err
	}
	x, err := readBigInt(reader)
	if err != nil {
		return OTSenderSetup{}, err
	}
	y, err := readBigInt(reader)
	if err != nil {
		return OTSenderSetup{}, err
	}

	return OTSenderSetup{
		CurveName: string(name),
		A: ot.ECPoint{
			X: x,
			Y: y,
		},
	}, nil
}

// writeChunk writes a length-prefixed byte slice.
func writeChunk(buf *bytes.Buffer, data []byte) {
	var header [4]byte
	byteOrder.PutUint32(header[:], uint32(len(data)))
	buf.Write(header[:])
	buf.Write(data)
}

// readChunk reads a single length-prefixed byte slice.
func readChunk(r *bytes.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := r.Read(header[:]); err != nil {
		return nil, err
	}
	length := int(byteOrder.Uint32(header[:]))
	data := make([]byte, length)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}

	return data, nil
}

// writeBigInt writes a length-prefixed big integer.
func writeBigInt(buf *bytes.Buffer, v *big.Int) {
	if v == nil {
		writeChunk(buf, nil)
		return
	}
	writeChunk(buf, v.Bytes())
}

// readBigInt reads a length-prefixed big integer.
func readBigInt(r *bytes.Reader) (*big.Int, error) {
	data, err := readChunk(r)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return big.NewInt(0), nil
	}

	return new(big.Int).SetBytes(data), nil
}

// encodeCOSenderSetup serializes the CO sender setup.
func encodeCOSenderSetup(setup ot.COSenderSetup) []byte {
	var buf bytes.Buffer
	writeChunk(&buf, []byte(setup.CurveName))
	writeBigInt(&buf, setup.Scalar)
	writeBigInt(&buf, setup.Ax)
	writeBigInt(&buf, setup.Ay)
	writeBigInt(&buf, setup.AaInvX)
	writeBigInt(&buf, setup.AaInvY)

	return buf.Bytes()
}

// decodeCOSenderSetup rebuilds a CO sender setup from bytes.
func decodeCOSenderSetup(data []byte) (ot.COSenderSetup, error) {
	reader := bytes.NewReader(data)

	name, err := readChunk(reader)
	if err != nil {
		return ot.COSenderSetup{}, err
	}

	scalar, err := readBigInt(reader)
	if err != nil {
		return ot.COSenderSetup{}, err
	}

	ax, err := readBigInt(reader)
	if err != nil {
		return ot.COSenderSetup{}, err
	}

	ay, err := readBigInt(reader)
	if err != nil {
		return ot.COSenderSetup{}, err
	}

	ainvx, err := readBigInt(reader)
	if err != nil {
		return ot.COSenderSetup{}, err
	}

	ainvy, err := readBigInt(reader)
	if err != nil {
		return ot.COSenderSetup{}, err
	}

	return ot.COSenderSetup{
		CurveName: string(name),
		Scalar:    scalar,
		Ax:        ax,
		Ay:        ay,
		AaInvX:    ainvx,
		AaInvY:    ainvy,
	}, nil
}

// encodeChoiceBundle serializes a CO choice bundle.
func encodeChoiceBundle(bundle ot.COChoiceBundle) []byte {
	var buf bytes.Buffer
	writeChunk(&buf, []byte(bundle.CurveName))
	writeBigInt(&buf, bundle.Ax)
	writeBigInt(&buf, bundle.Ay)

	var header [4]byte
	byteOrder.PutUint32(header[:], uint32(len(bundle.Scalars)))
	buf.Write(header[:])
	for _, scalar := range bundle.Scalars {
		writeBigInt(&buf, scalar)
	}

	byteOrder.PutUint32(header[:], uint32(len(bundle.Bits)))
	buf.Write(header[:])
	buf.Write(bitsToBytesLittle(bundle.Bits))

	return buf.Bytes()
}

// decodeChoiceBundle restores a CO choice bundle from bytes.
func decodeChoiceBundle(data []byte) (ot.COChoiceBundle, error) {
	reader := bytes.NewReader(data)

	name, err := readChunk(reader)
	if err != nil {
		return ot.COChoiceBundle{}, err
	}

	ax, err := readBigInt(reader)
	if err != nil {
		return ot.COChoiceBundle{}, err
	}

	ay, err := readBigInt(reader)
	if err != nil {
		return ot.COChoiceBundle{}, err
	}

	var header [4]byte
	if _, err := reader.Read(header[:]); err != nil {
		return ot.COChoiceBundle{}, err
	}

	scalarCount := int(byteOrder.Uint32(header[:]))
	scalars := make([]*big.Int, scalarCount)
	for i := 0; i < scalarCount; i++ {
		value, err := readBigInt(reader)
		if err != nil {
			return ot.COChoiceBundle{}, err
		}
		scalars[i] = value
	}
	if _, err := reader.Read(header[:]); err != nil {
		return ot.COChoiceBundle{}, err
	}

	bitsCount := int(byteOrder.Uint32(header[:]))
	bits := make([]bool, bitsCount)
	byteLen := (bitsCount + 7) / 8
	raw := make([]byte, byteLen)
	if _, err := reader.Read(raw); err != nil {
		return ot.COChoiceBundle{}, err
	}
	copy(bits, bytesToBitsLittle(raw))

	return ot.COChoiceBundle{
		CurveName: string(name),
		Ax:        ax,
		Ay:        ay,
		Scalars:   scalars,
		Bits:      bits,
	}, nil
}
