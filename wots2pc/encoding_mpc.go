package wots2pc

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/ot"
)

const chunkSizeLimit = 1 * 1024 * 1024

// EncodeRound1 turns a Round1Payload into bytes.
func EncodeRound1(curve elliptic.Curve, p Round1Payload) ([]byte, error) {
	if curve == nil {
		return nil, errNilCurve
	}
	var buf bytes.Buffer
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], p.SessionID)
	buf.Write(sid[:])
	writeChunk(&buf, encodePublic(p.Public))
	writeChunk(&buf, encodeMeta(p.Meta))
	if err := encodeOTSetup(&buf, curve, p.OT); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeRound1 reconstructs a Round1Payload from bytes.
func DecodeRound1(curve elliptic.Curve, data []byte) (Round1Payload, error) {
	if curve == nil {
		return Round1Payload{}, errNilCurve
	}
	reader := bytes.NewReader(data)
	var payload Round1Payload
	var sidBuf [8]byte
	if _, err := io.ReadFull(reader, sidBuf[:]); err != nil {
		return Round1Payload{}, err
	}
	pubChunk, err := readChunk(reader)
	if err != nil {
		return Round1Payload{}, err
	}
	metaChunk, err := readChunk(reader)
	if err != nil {
		return Round1Payload{}, err
	}
	if payload.Public, err = decodePublic(pubChunk); err != nil {
		return Round1Payload{}, err
	}
	if payload.Meta, err = decodeMeta(metaChunk); err != nil {
		return Round1Payload{}, err
	}
	payload.OT, err = decodeOTSetup(curve, reader)
	if err != nil {
		return Round1Payload{}, err
	}
	if payload.OT.CurveName != curve.Params().Name {
		return Round1Payload{}, fmt.Errorf("wots2pc: round1 curve mismatch %s vs %s", payload.OT.CurveName, curve.Params().Name)
	}
	payload.SessionID = binary.BigEndian.Uint64(sidBuf[:])
	return payload, nil
}

// EncodeRound2 turns a Round2Payload into bytes.
func EncodeRound2(curve elliptic.Curve, p Round2Payload) ([]byte, error) {
	if curve == nil {
		return nil, errNilCurve
	}
	var buf bytes.Buffer
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], p.SessionID)
	buf.Write(sid[:])
	writeChunk(&buf, encodePublic(p.Public))
	writeChunk(&buf, encodeMeta(p.Meta))
	writeChunk(&buf, []byte(curve.Params().Name))
	if err := encodePoints(curve, &buf, p.Choices); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeRound2 reconstructs a Round2Payload.
func DecodeRound2(curve elliptic.Curve, data []byte) (Round2Payload, error) {
	if curve == nil {
		return Round2Payload{}, errNilCurve
	}
	reader := bytes.NewReader(data)
	var sidBuf [8]byte
	if _, err := io.ReadFull(reader, sidBuf[:]); err != nil {
		return Round2Payload{}, err
	}
	pubChunk, err := readChunk(reader)
	if err != nil {
		return Round2Payload{}, err
	}
	metaChunk, err := readChunk(reader)
	if err != nil {
		return Round2Payload{}, err
	}
	nameChunk, err := readChunk(reader)
	if err != nil {
		return Round2Payload{}, err
	}
	curveName := string(nameChunk)
	if curveName != curve.Params().Name {
		return Round2Payload{}, fmt.Errorf("wots2pc: round2 curve mismatch %s vs %s", curveName, curve.Params().Name)
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		return Round2Payload{}, err
	}
	points, err := decodePoints(curve, rest)
	if err != nil {
		return Round2Payload{}, err
	}
	public, err := decodePublic(pubChunk)
	if err != nil {
		return Round2Payload{}, err
	}
	meta, err := decodeMeta(metaChunk)
	if err != nil {
		return Round2Payload{}, err
	}
	return Round2Payload{
		SessionID: binary.BigEndian.Uint64(sidBuf[:]),
		CurveName: curveName,
		Choices:   points,
		Public:    public,
		Meta:      meta,
	}, nil
}

// EncodeRound3 turns a Round3Payload into bytes.
func EncodeRound3(p Round3Payload) ([]byte, error) {
	var buf bytes.Buffer
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], p.SessionID)
	buf.Write(sid[:])
	buf.Write(p.Key[:])
	writeChunk(&buf, encodePublic(p.Public))
	writeChunk(&buf, encodeMeta(p.Meta))
	if err := encodeGarbledTables(&buf, p.GarbledTables); err != nil {
		return nil, err
	}
	if err := encodeLabels(&buf, p.GarblerInputs); err != nil {
		return nil, err
	}
	if err := encodeOutputHints(&buf, p.PublicInputs); err != nil {
		return nil, err
	}
	if err := encodeOutputHints(&buf, p.OutputHints); err != nil {
		return nil, err
	}
	if err := encodeCiphertexts(&buf, p.Ciphertexts); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeRound3 reconstructs a Round3Payload from bytes.
func DecodeRound3(data []byte) (Round3Payload, error) {
	var payload Round3Payload
	reader := bytes.NewReader(data)
	var sid [8]byte
	if _, err := io.ReadFull(reader, sid[:]); err != nil {
		return Round3Payload{}, err
	}
	payload.SessionID = binary.BigEndian.Uint64(sid[:])
	if _, err := io.ReadFull(reader, payload.Key[:]); err != nil {
		return Round3Payload{}, err
	}
	pubChunk, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	metaChunk, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	tables, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.GarbledTables, err = decodeGarbledTables(tables)
	if err != nil {
		return Round3Payload{}, err
	}
	lblChunk, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.GarblerInputs, err = decodeLabels(lblChunk)
	if err != nil {
		return Round3Payload{}, err
	}
	pubInputs, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.PublicInputs, err = decodeOutputHints(pubInputs)
	if err != nil {
		return Round3Payload{}, err
	}
	hintsChunk, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.OutputHints, err = decodeOutputHints(hintsChunk)
	if err != nil {
		return Round3Payload{}, err
	}
	ctChunk, err := readChunk(reader)
	if err != nil {
		return Round3Payload{}, err
	}
	payload.Ciphertexts, err = decodeCiphertexts(ctChunk)
	if err != nil {
		return Round3Payload{}, err
	}
	if payload.Public, err = decodePublic(pubChunk); err != nil {
		return Round3Payload{}, err
	}
	if payload.Meta, err = decodeMeta(metaChunk); err != nil {
		return Round3Payload{}, err
	}
	return payload, nil
}

func encodeOTSetup(writer io.Writer, curve elliptic.Curve, otSetup OTSenderSetup) error {
	writeChunk(writer, []byte(otSetup.CurveName))
	writeChunk(writer, otSetup.A.X.Bytes())
	writeChunk(writer, otSetup.A.Y.Bytes())
	return nil
}

func decodeOTSetup(curve elliptic.Curve, reader io.Reader) (OTSenderSetup, error) {
	name, err := readChunk(reader)
	if err != nil {
		return OTSenderSetup{}, err
	}
	xBytes, err := readChunk(reader)
	if err != nil {
		return OTSenderSetup{}, err
	}
	yBytes, err := readChunk(reader)
	if err != nil {
		return OTSenderSetup{}, err
	}
	return OTSenderSetup{
		CurveName: string(name),
		A: ot.ECPoint{
			X: new(big.Int).SetBytes(xBytes),
			Y: new(big.Int).SetBytes(yBytes),
		},
	}, nil
}

func encodeGarbledTables(buf *bytes.Buffer, tables [][]ot.Label) error {
	var tmp bytes.Buffer
	for _, table := range tables {
		for _, l := range table {
			var data ot.LabelData
			binary.BigEndian.PutUint64(data[0:8], l.D0)
			binary.BigEndian.PutUint64(data[8:16], l.D1)
			tmp.Write(data[:])
		}
	}
	writeChunk(buf, tmp.Bytes())
	return nil
}

func decodeGarbledTables(data []byte) ([][]ot.Label, error) {
	var tables [][]ot.Label
	// We cannot recover per-gate sizes without circuit; rely on linear layout.
	labelCount := len(data) / labelByteLen
	if labelCount*labelByteLen != len(data) {
		return nil, fmt.Errorf("garbled tables length mismatch")
	}
	table := make([]ot.Label, labelCount)
	offset := 0
	for i := 0; i < labelCount; i++ {
		table[i].D0 = binary.BigEndian.Uint64(data[offset:])
		table[i].D1 = binary.BigEndian.Uint64(data[offset+8:])
		offset += labelByteLen
	}
	// Single flattened table; circuit parser uses gate boundaries internally.
	tables = append(tables, table)
	return tables, nil
}

func encodeLabels(buf *bytes.Buffer, labels []ot.Label) error {
	var tmp bytes.Buffer
	for _, l := range labels {
		var data ot.LabelData
		binary.BigEndian.PutUint64(data[0:8], l.D0)
		binary.BigEndian.PutUint64(data[8:16], l.D1)
		tmp.Write(data[:])
	}
	writeChunk(buf, tmp.Bytes())
	return nil
}

func decodeLabels(data []byte) ([]ot.Label, error) {
	if len(data)%labelByteLen != 0 {
		return nil, fmt.Errorf("decodeLabels: invalid length %d", len(data))
	}
	count := len(data) / labelByteLen
	out := make([]ot.Label, count)
	offset := 0
	for i := 0; i < count; i++ {
		out[i].D0 = binary.BigEndian.Uint64(data[offset:])
		out[i].D1 = binary.BigEndian.Uint64(data[offset+8:])
		offset += labelByteLen
	}
	return out, nil
}

func encodeOutputHints(buf *bytes.Buffer, wires []ot.Wire) error {
	var tmp bytes.Buffer
	for _, w := range wires {
		var data ot.LabelData
		binary.BigEndian.PutUint64(data[0:8], w.L0.D0)
		binary.BigEndian.PutUint64(data[8:16], w.L0.D1)
		tmp.Write(data[:])
		binary.BigEndian.PutUint64(data[0:8], w.L1.D0)
		binary.BigEndian.PutUint64(data[8:16], w.L1.D1)
		tmp.Write(data[:])
	}
	writeChunk(buf, tmp.Bytes())
	return nil
}

func decodeOutputHints(data []byte) ([]ot.Wire, error) {
	if len(data)%(labelByteLen*2) != 0 {
		return nil, fmt.Errorf("decodeOutputHints: invalid length %d", len(data))
	}
	count := len(data) / (labelByteLen * 2)
	out := make([]ot.Wire, count)
	offset := 0
	for i := 0; i < count; i++ {
		out[i].L0.D0 = binary.BigEndian.Uint64(data[offset:])
		out[i].L0.D1 = binary.BigEndian.Uint64(data[offset+8:])
		offset += labelByteLen
		out[i].L1.D0 = binary.BigEndian.Uint64(data[offset:])
		out[i].L1.D1 = binary.BigEndian.Uint64(data[offset+8:])
		offset += labelByteLen
	}
	return out, nil
}

func encodeCiphertexts(buf *bytes.Buffer, cts []ot.LabelCiphertext) error {
	var tmp bytes.Buffer
	for _, ct := range cts {
		tmp.Write(ct.Zero[:])
		tmp.Write(ct.One[:])
	}
	writeChunk(buf, tmp.Bytes())
	return nil
}

func decodeCiphertexts(data []byte) ([]ot.LabelCiphertext, error) {
	if len(data)%(labelByteLen*2) != 0 {
		return nil, fmt.Errorf("decodeCiphertexts: invalid length %d", len(data))
	}
	count := len(data) / (labelByteLen * 2)
	out := make([]ot.LabelCiphertext, count)
	offset := 0
	for i := 0; i < count; i++ {
		copy(out[i].Zero[:], data[offset:])
		offset += labelByteLen
		copy(out[i].One[:], data[offset:])
		offset += labelByteLen
	}
	return out, nil
}

func writeChunk(w io.Writer, data []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	w.Write(size[:])
	w.Write(data)
}

func readChunk(r io.Reader) ([]byte, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(sizeBuf[:])
	if size > chunkSizeLimit {
		return nil, fmt.Errorf("chunk too large: %d", size)
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func encodePublic(p PublicData) []byte {
	var buf bytes.Buffer
	buf.Write(p.PubSeed[:])
	buf.Write(p.Addr[:])
	return buf.Bytes()
}

func decodePublic(data []byte) (PublicData, error) {
	if len(data) != 64 {
		return PublicData{}, fmt.Errorf("public data length %d", len(data))
	}
	var p PublicData
	copy(p.PubSeed[:], data[:32])
	copy(p.Addr[:], data[32:])
	return p, nil
}

func encodeMeta(m CircuitMeta) []byte {
	var buf bytes.Buffer
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(m.Gates))
	buf.Write(tmp[:])
	binary.BigEndian.PutUint32(tmp[:], uint32(m.Wires))
	buf.Write(tmp[:])
	buf.Write(m.Hash[:])
	return buf.Bytes()
}

func decodeMeta(data []byte) (CircuitMeta, error) {
	if len(data) != 4+4+32 {
		return CircuitMeta{}, fmt.Errorf("meta length %d", len(data))
	}
	var m CircuitMeta
	m.Gates = int(binary.BigEndian.Uint32(data[0:4]))
	m.Wires = int(binary.BigEndian.Uint32(data[4:8]))
	copy(m.Hash[:], data[8:])
	return m, nil
}

// encodePoints serializes EC points into buf using fixed-width X coordinates
// with zero padding so the result is deterministic.
func encodePoints(curve elliptic.Curve, buf *bytes.Buffer, points []ot.ECPoint) error {
	byteLen := (curve.Params().BitSize + 7) / 8
	writeChunk(buf, []byte{byte(byteLen)})
	tmp := make([]byte, byteLen)
	for _, p := range points {
		tmp = tmp[:byteLen]
		copyWithPadding(tmp, p.X.Bytes())
		writeChunk(buf, tmp)
		copyWithPadding(tmp, p.Y.Bytes())
		writeChunk(buf, tmp)
	}
	return nil
}

// decodePoints reconstructs EC points serialized by encodePoints.
func decodePoints(curve elliptic.Curve, data []byte) ([]ot.ECPoint, error) {
	reader := bytes.NewReader(data)
	byteLenChunk, err := readChunk(reader)
	if err != nil {
		return nil, err
	}
	byteLen := int(byteLenChunk[0])
	if byteLen != (curve.Params().BitSize+7)/8 {
		return nil, fmt.Errorf("wots2pc: curve size mismatch")
	}
	var points []ot.ECPoint
	for {
		xChunk, err := readChunk(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		yChunk, err := readChunk(reader)
		if err != nil {
			return nil, err
		}
		points = append(points, ot.ECPoint{
			X: new(big.Int).SetBytes(xChunk),
			Y: new(big.Int).SetBytes(yChunk),
		})
	}
	return points, nil
}

func copyWithPadding(dst, src []byte) {
	if len(src) > len(dst) {
		copy(dst, src[len(src)-len(dst):])
		return
	}
	padding := len(dst) - len(src)
	for i := 0; i < padding; i++ {
		dst[i] = 0
	}
	copy(dst[padding:], src)
}
