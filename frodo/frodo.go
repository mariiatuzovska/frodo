package frodo

import (
	"math"
	"math/big"
	"math/bits"
)

type Frodo interface { // all funcs for this pkg

	Encode(k *big.Int) [][]uint16 // encodes an integer 0 ≤ k < 2^B as an element in Zq by multiplying it by q/2B = 2^(D−B): ec(k) := k·q/2^B
	Decode(K [][]uint16) *big.Int // decodes the m-by-n matrix K into a bit string of length l = B·m·n. dc(c) = ⌊c·2^B/q⌉ mod 2^B
	Pack()
	Unpack()
	Sample()
	SampleMatrix()
}

type Parameters struct {
	no      int    // n ≡ 0 (mod 8)
	q       uint32 // a power-of-two integer modulus with exponent D ≤ 16
	D       int    // a power
	m, n    int    // integer matrix dimensions with
	B       int    // the number of bits encoded in each matrix entry
	l       int    // B·m·n, the length of bit strings that are encoded as m-by-n matrices
	lseedA  int    // the bit length of seeds used for pseudorandom matrix generation
	lseedSE int    // the bit length of seeds used for pseudorandom bit generation for error sampling
	x       uint16 // a probability distribution on Z
}

func Frodo640() *Parameters {

	param := new(Parameters)

	param.no = 640
	param.q = 32768
	param.D = 15
	param.B = 2
	param.m = 8
	param.n = 8
	param.lseedA = 128
	param.lseedSE = 128
	param.l = 128

	return param
}

func Frodo976() *Parameters {

	param := new(Parameters)

	param.no = 976
	param.q = 65536
	param.D = 16
	param.B = 3
	param.m = 8
	param.n = 8
	param.lseedA = 128
	param.lseedSE = 128
	param.l = 128

	return param
}

func Frodo1344() *Parameters {

	param := new(Parameters)

	param.no = 1344
	param.q = 65536
	param.D = 16
	param.B = 4
	param.m = 8
	param.n = 8
	param.lseedA = 128
	param.lseedSE = 128
	param.l = 128

	return param
}

func (param *Parameters) Encode(k *big.Int) [][]uint16 {

	K := make([][]uint16, param.m)

	for i := range K {
		K[i] = make([]uint16, param.n)
		for j := range K[i] {
			temp, c := uint16(0), uint16(1)
			for l := 0; l < param.B; l++ {
				if (k.Bit((i*param.n+j)*param.B + l)) == 1 {
					temp += c
				}
				c *= 2
			}
			K[i][j] = param.ec(temp)
		}
	}
	return K
}

func (param *Parameters) Decode(K [][]uint16) *big.Int {

	k := big.NewInt(0)

	return k
}

func (param *Parameters) ec(k uint16) uint16 {

	B := bits.Len16(k)
	exp := param.D - B

	return k * uint16(uint32(math.Pow(2, float64(exp)))%param.q)
}
