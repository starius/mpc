package sha2pc

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

// byteOrder specifies the serialization endianness shared across helpers.
var byteOrder = binary.BigEndian

// encodeLabels flattens labels into a raw byte slice.
func encodeLabels(labels []ot.Label) []byte {
	buf := make([]byte, 0, len(labels)*16)
	var tmp ot.LabelData
	for _, l := range labels {
		l.GetData(&tmp)
		buf = append(buf, tmp[:]...)
	}
	return buf
}

// decodeLabels reconstructs labels from a serialized slice.
func decodeLabels(data []byte) ([]ot.Label, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("label buffer not 16-byte aligned")
	}
	count := len(data) / 16
	result := make([]ot.Label, count)
	var tmp ot.LabelData
	for i := 0; i < count; i++ {
		copy(tmp[:], data[i*16:(i+1)*16])
		result[i].SetData(&tmp)
	}
	return result, nil
}

// encodeGarbledTables serializes all garbled tables.
func encodeGarbledTables(tables [][]ot.Label) []byte {
	var buf bytes.Buffer

	var hdr [4]byte
	byteOrder.PutUint32(hdr[:], uint32(len(tables)))
	buf.Write(hdr[:])

	var tmp ot.LabelData
	for _, row := range tables {
		byteOrder.PutUint32(hdr[:], uint32(len(row)))
		buf.Write(hdr[:])

		for _, label := range row {
			label.GetData(&tmp)
			buf.Write(tmp[:])
		}
	}
	return buf.Bytes()
}

// decodeGarbledTables restores garbled tables from bytes.
func decodeGarbledTables(data []byte) ([][]ot.Label, error) {
	r := bytes.NewReader(data)
	var hdr [4]byte
	if _, err := r.Read(hdr[:]); err != nil {
		return nil, err
	}
	numGates := int(byteOrder.Uint32(hdr[:]))
	result := make([][]ot.Label, numGates)

	var tmp ot.LabelData
	for i := 0; i < numGates; i++ {
		if _, err := r.Read(hdr[:]); err != nil {
			return nil, err
		}
		count := int(byteOrder.Uint32(hdr[:]))
		if count == 0 {
			continue
		}
		row := make([]ot.Label, count)
		for j := 0; j < count; j++ {
			if _, err := r.Read(tmp[:]); err != nil {
				return nil, err
			}
			row[j].SetData(&tmp)
		}
		result[i] = row
	}
	return result, nil
}

// encodeOutputHints records each output wire's label pair.
func encodeOutputHints(wires []ot.Wire) []byte {
	var buf bytes.Buffer
	var hdr [4]byte
	byteOrder.PutUint32(hdr[:], uint32(len(wires)))
	buf.Write(hdr[:])
	var tmp ot.LabelData
	for _, wire := range wires {
		wire.L0.GetData(&tmp)
		buf.Write(tmp[:])
		wire.L1.GetData(&tmp)
		buf.Write(tmp[:])
	}
	return buf.Bytes()
}

// decodeOutputHints rebuilds output wires from serialized data.
func decodeOutputHints(data []byte) ([]ot.Wire, error) {
	r := bytes.NewReader(data)
	var hdr [4]byte
	if _, err := r.Read(hdr[:]); err != nil {
		return nil, err
	}
	count := int(byteOrder.Uint32(hdr[:]))
	result := make([]ot.Wire, count)
	var tmp ot.LabelData
	for i := 0; i < count; i++ {
		if _, err := r.Read(tmp[:]); err != nil {
			return nil, err
		}
		result[i].L0.SetData(&tmp)
		if _, err := r.Read(tmp[:]); err != nil {
			return nil, err
		}
		result[i].L1.SetData(&tmp)
	}
	return result, nil
}

// selectOutputWires chooses the wires that correspond to circuit outputs.
func selectOutputWires(circ *circuit.Circuit, garbled *circuit.Garbled) []ot.Wire {
	outputs := circ.Outputs.Size()
	result := make([]ot.Wire, outputs)
	start := int(circ.NumWires) - outputs
	copy(result, garbled.Wires[start:])
	return result
}

// encodePoints serializes elliptic-curve points.
func encodePoints(points []ecPoint) []byte {
	var buf bytes.Buffer
	var hdr [4]byte
	byteOrder.PutUint32(hdr[:], uint32(len(points)))
	buf.Write(hdr[:])
	for _, p := range points {
		writeBigInt(&buf, p.x)
		writeBigInt(&buf, p.y)
	}
	return buf.Bytes()
}

// decodePoints rebuilds points from a byte slice.
func decodePoints(data []byte) ([]ecPoint, error) {
	r := bytes.NewReader(data)
	var hdr [4]byte
	if _, err := r.Read(hdr[:]); err != nil {
		return nil, err
	}
	count := int(byteOrder.Uint32(hdr[:]))
	result := make([]ecPoint, count)
	for i := 0; i < count; i++ {
		x, err := readBigInt(r)
		if err != nil {
			return nil, err
		}
		y, err := readBigInt(r)
		if err != nil {
			return nil, err
		}
		result[i] = ecPoint{x: x, y: y}
	}
	return result, nil
}

// writeBigInt writes a length-prefixed big integer.
func writeBigInt(buf *bytes.Buffer, val *big.Int) {
	data := val.Bytes()
	var hdr [4]byte
	byteOrder.PutUint32(hdr[:], uint32(len(data)))
	buf.Write(hdr[:])
	buf.Write(data)
}

// readBigInt reads a length-prefixed big integer.
func readBigInt(r *bytes.Reader) (*big.Int, error) {
	var hdr [4]byte
	if _, err := r.Read(hdr[:]); err != nil {
		return nil, err
	}
	length := int(byteOrder.Uint32(hdr[:]))
	data := make([]byte, length)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

// encodeOTSetup serializes the OT curve name and the sender point A.
func encodeOTSetup(curve elliptic.Curve, Ax, Ay *big.Int) []byte {
	var buf bytes.Buffer
	writeChunk(&buf, []byte(curve.Params().Name))
	writeBigInt(&buf, Ax)
	writeBigInt(&buf, Ay)
	return buf.Bytes()
}

// decodeOTSetup parses the curve name and sender point A from bytes.
func decodeOTSetup(data []byte) (string, *big.Int, *big.Int, error) {
	r := bytes.NewReader(data)
	name, err := readChunk(r)
	if err != nil {
		return "", nil, nil, err
	}
	Ax, err := readBigInt(r)
	if err != nil {
		return "", nil, nil, err
	}
	Ay, err := readBigInt(r)
	if err != nil {
		return "", nil, nil, err
	}
	return string(name), Ax, Ay, nil
}

// writeChunk emits a generic length-prefixed chunk.
func writeChunk(buf *bytes.Buffer, data []byte) {
	var hdr [4]byte
	byteOrder.PutUint32(hdr[:], uint32(len(data)))
	buf.Write(hdr[:])
	buf.Write(data)
}

// readChunk parses a generic length-prefixed chunk.
func readChunk(r *bytes.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := r.Read(hdr[:]); err != nil {
		return nil, err
	}
	length := int(byteOrder.Uint32(hdr[:]))
	data := make([]byte, length)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}
