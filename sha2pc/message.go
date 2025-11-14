package sha2pc

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Message represents an opaque protocol payload that callers forward
// to the other participant using their preferred transport. The first
// byte encodes the version, the second byte the round identifier, and
// the remaining bytes contain round-specific data.
type Message []byte

const (
	// messageVersion identifies the binary format version stored in every Message.
	messageVersion byte = 1

	// round1Kind categorizes round-one payloads that carry the garbled circuit.
	round1Kind byte = 1
	// round2Kind categorizes round-two payloads that carry OT requests.
	round2Kind byte = 2
	// round3Kind categorizes round-three payloads that carry OT responses.
	round3Kind byte = 3
	// round4Kind categorizes round-four payloads that carry the final hash share.
	round4Kind byte = 4
)

// newMessage wraps the payload with a versioned header.
func newMessage(kind byte, payload []byte) Message {
	buf := make([]byte, 0, 2+len(payload))
	buf = append(buf, messageVersion, kind)
	return append(buf, payload...)
}

// parseMessage validates the message header and returns the payload.
func parseMessage(msg Message, expectedKind byte) ([]byte, error) {
	if len(msg) < 2 {
		return nil, fmt.Errorf("invalid message: too short")
	}
	if msg[0] != messageVersion {
		return nil, fmt.Errorf("unsupported message version %d", msg[0])
	}
	if msg[1] != expectedKind {
		return nil, fmt.Errorf("unexpected message kind %d", msg[1])
	}
	return msg[2:], nil
}

// chunkReader deserializes length-prefixed byte slices.
type chunkReader struct {
	// Reader provides sequential access to the serialized chunk stream.
	*bytes.Reader
}

// newChunkReader constructs a chunk reader for the provided byte slice.
func newChunkReader(data []byte) *chunkReader {
	return &chunkReader{
		Reader: bytes.NewReader(data),
	}
}

// readChunk returns the next chunk or nil when the encoded length is zero.
func (r *chunkReader) readChunk() ([]byte, error) {
	var hdr [4]byte
	if _, err := r.Read(hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length == 0 {
		return nil, nil
	}
	data := make([]byte, length)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}
