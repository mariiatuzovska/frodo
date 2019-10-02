package bitstr

import (
	"fmt"
	"math/bits"
	"math/rand"
	"time"
)

// BitString contains little-endian order of 16-bit elements in string
type BitString struct {
	str []uint16
	len int
}

// New returns BitString struct
func New(length int) *BitString {
	b := new(BitString)
	b.len = length / 16
	b.str = make([]uint16, b.len)
	return b
}

// NewRand returns BitString struct with random *ha-ha* bits
func NewRand(length int) *BitString {

	b := new(BitString)
	b.len = length / 16
	b.str = make([]uint16, b.len)
	b.rand()
	return b
}

func (b *BitString) rand() {
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range b.str {
		b.str[i] = uint16(rand.Int31())
	}
}

// SetReversedUint16 sets a 16-bit number with little-endian order to BitString struct
func (b *BitString) SetReversedUint16(index int, value uint16) {
	b.str[index] = bits.Reverse16(value)
}

// GetReversedUint16 returns a 16-bit reversed uint16
func (b *BitString) GetReversedUint16(index int) uint16 {
	return bits.Reverse16(b.str[index])
}

// SetUint16 sets a uint16 into some index
func (b *BitString) SetUint16(index int, value uint16) {
	b.str[index] = value
}

// GetUint16 returns uint16 that are in the index (index)
func (b *BitString) GetUint16(index int) uint16 {
	return b.str[index]
}

// GetBytes returns BitString struct as a []byte
func (b *BitString) GetBytes() []byte {

	bytes := make([]byte, b.len*2)
	for i, value := range b.str {
		bytes[i*2] = byte(value >> 8)
		bytes[i*2+1] = byte(value)
	}
	return bytes
}

// SetBytes sets []byte into BitString struct
func (b *BitString) SetBytes(bytes []byte) {
	for i := 0; i < b.len; i++ {
		b.str[i] = (uint16(bytes[i*2]) << 8) + uint16(bytes[i*2+1])
	}
}

// SetBytesHalf sets []byte array into BitString struct
// a is first index of byte arr & (c - 1) is the last index of byte arr
func (b *BitString) SetBytesHalf(bytes []byte, a, c int) {
	for i := 0; i < b.len; i++ {
		b.str[i] = (uint16(bytes[a+(i*2)]) << 8) + uint16(bytes[a+(i*2)+1])
	}
}

// Get2Bytes returns uint16 in index (index) as two bytes ([]byte)
func (b *BitString) Get2Bytes(index int) []byte {
	bytes := make([]byte, 2)
	bytes[0] = byte(b.str[index] >> 8)
	bytes[1] = byte(b.str[index])
	return bytes
}

// ConcatUint16First concatenate input uint16 with BitString
func (b *BitString) ConcatUint16(u uint16) {

	temp := New(b.Len() + 16)
	temp.str[0] = u
	for i := 0; i < b.len; i++ {
		temp.str[i+1] = b.str[i]
	}
	b = temp
}

// Len returns len (count of bits) of bitstring
func (b *BitString) Len() int {
	return b.len * 16
}

// BitLen returns first figest not null index of bit
func (b *BitString) BitLen() int {

	k := b.len
	for i := k - 1; i > -1; i-- {
		if bits.Len16(b.str[i]) != 0 {
			return i * bits.Len16(b.str[i])
		}
	}
	return 0
}

// Bit returns the bit type int in position n
func (b *BitString) Bit(n int) int {
	if (0x8000>>uint(n%16))&b.str[n/16] != 0 {
		return 1
	}
	return 0
}

// SetBit sets the bit (bit) at index n in BitString
func (b *BitString) SetBit(n int, bit int) {

	temp := uint16(0x8000) >> uint(n%16)
	if bit == 0 {
		temp ^= 0xffff
		b.str[n/16] = b.str[n/16] & temp
	} else {
		b.str[n/16] = b.str[n/16] | temp
	}
}

// PrintBit prints a BitString as bit sequence in not clever order XD, in future i will delete this func
// this is for debug
func (b *BitString) PrintBit() {
	fmt.Printf("%b\n", b.str)
}

// PrintHex prints a BitString as hex sequence in not clever order XD, in future i will delete this func
// this is for debug
func (b *BitString) PrintHex() {
	fmt.Printf("%x\n", b.str)
}
