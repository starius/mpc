package wots2pc

// bytesToBitsLittle converts bytes to bits, least significant bit first.
func bytesToBitsLittle(data []byte) []bool {
	bits := make([]bool, 0, len(data)*8)
	for _, b := range data {
		for i := 0; i < 8; i++ {
			bits = append(bits, ((b>>i)&1) == 1)
		}
	}
	return bits
}

// bitsToBytesLittle packs bits (lsb-first per byte) into bytes.
func bitsToBytesLittle(bits []bool) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, bit := range bits {
		if bit {
			out[i/8] |= 1 << (uint(i) % 8)
		}
	}
	return out
}
