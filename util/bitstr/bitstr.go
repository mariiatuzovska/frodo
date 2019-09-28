package bitstr

import (
	"fmt"
	"math/bits"
)

// little-endian order of 16-bit elements in string

type BitString struct {
	str []uint16
	len int
}

func New(length int) *BitString {
	b := new(BitString)
	b.str = make([]uint16, length)
	b.len = length
	return b
}

func (b *BitString) Uint16(index int, value uint16) { // the 16-bit with little-endian order
	c := bits.Reverse16(value)
	b.str[index] = c
}

func (b *BitString) Len() int {

	k := len(b.str)
	for i := k - 1; i > -1; i-- {
		if bits.Len16(b.str[i]) != 0 {
			return i * bits.Len16(b.str[i])
		}
	}
	return 0
}

func (b *BitString) Get() []uint16 {
	return b.str
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
	fmt.Println(fmt.Sprintf("%b", b.str))
}

func (b *BitString) PrintHex() {
	fmt.Println(fmt.Sprintf("%x", b.str))
}
