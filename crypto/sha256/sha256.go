package sha256

import (
	"encoding/binary"
	"math/bits"
)

/*
SHA-256 standard from:
https://csrc.nist.gov/pubs/fips/180-4/upd1/final
*/

// k constants from section 4.2.2
var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// initial hash values from section 5.3.3
var initH = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// Public API
func Sum256(msg []byte) [32]byte {
	// copy initH
	hash := initH

	msg = pad(msg)

	// pass 64 byte chunks of message at a time into compress
	for i := 0; i < len(msg); i += 64 {
		compress(&hash, (*[64]byte)(msg[i:i+64]))
	}

	var digest [32]byte

	for i := 0; i < len(hash); i++ {
		binary.BigEndian.PutUint32(digest[i*4:], hash[i])
	}

	return digest
}

// returns padded message, length a multiple of 64
func pad(msg []byte) []byte {
	msgLen := len(msg)

	p := make([]byte, msgLen, msgLen+72) // learn what this does
	copy(p, msg)

	p = append(p, 0x80)

	n := (55 - msgLen%64 + 64) % 64
	p = append(p, make([]byte, n)...)

	p = binary.BigEndian.AppendUint64(p, uint64(msgLen)*8) // check + err if overflow

	return p
}

// processes one 64-byte block, updates state in place
func compress(bigH *[8]uint32, block *[64]byte) {
	var w [64]uint32

	// w[i] for the first 16 words should be 4 byte chunks of the block
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}

	for i := 16; i < 64; i++ {
		w[i] = smallSigma1(w[i-2]) + w[i-7] + smallSigma0(w[i-15]) + w[i-16]
	}

	a, b, c, d, e, f, g, h := bigH[0], bigH[1], bigH[2], bigH[3], bigH[4], bigH[5], bigH[6], bigH[7]

	for i := 0; i < 64; i++ {
		t1 := h + bigSigma1(e) + ch(e, f, g) + k[i] + w[i]
		t2 := bigSigma0(a) + maj(a, b, c)

		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}

	bigH[0] = bigH[0] + a
	bigH[1] = bigH[1] + b
	bigH[2] = bigH[2] + c
	bigH[3] = bigH[3] + d
	bigH[4] = bigH[4] + e
	bigH[5] = bigH[5] + f
	bigH[6] = bigH[6] + g
	bigH[7] = bigH[7] + h
}

// The six logical functions (section 4.1.2)
func ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func bigSigma0(x uint32) uint32 {
	// ROTR^2(x) ^ ROTR^13(x) ^ ROTR^22(x)
	return bits.RotateLeft32(x, -2) ^ bits.RotateLeft32(x, -13) ^ bits.RotateLeft32(x, -22)
}

func bigSigma1(x uint32) uint32 {
	// ROTR^6(x) ^ ROTR^11(x) ^ ROTR^25(x)
	return bits.RotateLeft32(x, -6) ^ bits.RotateLeft32(x, -11) ^ bits.RotateLeft32(x, -25)
}

func smallSigma0(x uint32) uint32 {
	// ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)
	return bits.RotateLeft32(x, -7) ^ bits.RotateLeft32(x, -18) ^ (x >> 3)
}

func smallSigma1(x uint32) uint32 {
	// ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
	return bits.RotateLeft32(x, -17) ^ bits.RotateLeft32(x, -19) ^ (x >> 10)
}
