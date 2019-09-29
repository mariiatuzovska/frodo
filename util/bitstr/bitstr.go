package bitstr

import (
	"fmt"
	"math/bits"
	"math/rand"
)

type BitString struct { // little-endian order of 16-bit elements in string
	str []uint16
	len int
}

func New(length int) *BitString {
	b := new(BitString)
	b.len = length / 16
	b.str = make([]uint16, b.len)
	return b
}

func NewRand(length int) *BitString {
	b := new(BitString)
	b.len = length / 16
	b.str = make([]uint16, b.len)
	b.Rand()
	return b
}

func (b *BitString) Rand() {
	for i := range b.str {
		b.str[i] = uint16(rand.Int31())
	}
}

func (b *BitString) SetReversedUint16(index int, value uint16) { // sets a 16-bit number with little-endian order to bit string
	b.str[index] = bits.Reverse16(value)
}

func (b *BitString) GetReversedUint16(index int) uint16 { // returns a 16-bit reversed sub string as number
	return bits.Reverse16(b.str[index])
}

func (b *BitString) SetUint16(index int, value uint16) { // sets a 16-bit sub string
	b.str[index] = value
}

func (b *BitString) GetUint16(index int) uint16 { // gets a 16-bit sub string
	return b.str[index]
}

func (b *BitString) GetBytes() []byte {

	bytes := make([]byte, b.len*2)
	for i, value := range b.str {
		bytes[i*2] = byte(value >> 8)
		bytes[i*2+1] = byte(value)
	}
	return bytes
}

func (b *BitString) SetBytes(bytes []byte) {

	for i := 0; i < b.len; i++ {
		b.str[i] = (uint16(bytes[i*2]) << 8) + uint16(bytes[i*2+1])
	}
}

func (b *BitString) SetBytesHalf(bytes []byte, p int) {

	r := p * b.len
	for i := 0; i < b.len; i++ {
		b.str[i] = (uint16(bytes[i*2+r]) << 8) + uint16(bytes[i*2+r+1])
	}
}

func (b *BitString) Get2Bytes(index int) []byte {

	bytes := make([]byte, 2)
	bytes[0] = byte(b.str[index] >> 8)
	bytes[1] = byte(b.str[index])
	return bytes
}

func (b *BitString) Len() int {
	return b.len * 16
}

func (b *BitString) BitLen() int {

	k := b.len
	for i := k - 1; i > -1; i-- {
		if bits.Len16(b.str[i]) != 0 {
			return i * bits.Len16(b.str[i])
		}
	}
	return 0
}

func (b *BitString) Bit(n int) int {

	if (0x8000>>uint(n%16))&b.str[n/16] != 0 {
		return 1
	}
	return 0
}

func (b *BitString) SetBit(n int, bit int) {

	temp := uint16(0x8000) >> uint(n%16)
	if bit == 0 {
		temp ^= 0xffff
		b.str[n/16] = b.str[n/16] & temp
	} else {
		b.str[n/16] = b.str[n/16] | temp
	}
}

func (b *BitString) PrintBit() {
	fmt.Printf("%b\n", b.str)
}

func (b *BitString) PrintHex() {
	fmt.Printf("%x\n", b.str)
}
