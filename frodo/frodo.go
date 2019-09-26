package frodo

import (
	"log"
	"math"
	"math/big"
	"math/bits"
)

// пока что я решила : битовые строки это *big.Int
// размерность битовых строк int

type Frodo interface { // all funcs for this pkg
	Encode(k *big.Int) [][]uint16 // encodes an integer 0 ≤ k < 2^B as an element in Zq by multiplying it by q/2B = 2^(D−B): ec(k) := k·q/2^B
	Decode(K [][]uint16) uint16   // decodes the m-by-n matrix K into a bit string of length l = B·m·n. dc(c) = ⌊c·2^B/q⌉ mod 2^B
	Pack()
	Unpack()
	Sample()
	SampleMatrix()
}

type Parameters struct {
	x       []float32 // a probability distribution on Z
	q       uint16    // a power-of-two integer modulus with exponent D ≤ 16
	D       int       // a power
	m, n    int       // integer matrix dimensions with n ≡ 0 (mod 8)
	B       int       // the number of bits encoded in each matrix entry
	l       int       // B·m·n, the length of bit strings that are encoded as m-by-n matrices
	lseedA  int       // the bit length of seeds used for pseudorandom matrix generation
	lseedSE int       // the bit length of seeds used for pseudorandom bit generation for error sampling
}

func New() *Parameters {
	return new(Parameters)
}

func SetParameters(D int) *Parameters { //ongoing
	param := new(Parameters)
	if D > 17 {
		log.Fatal("power-of-two integer modulus must exponent D ≤ 16")
	}
	param.q = uint16(math.Pow(2, float64(D)))
	param.D = D
	//param.B = ??
	//param.m = ??
	//param.n = ??
	param.l = param.B * param.m * param.n
	return param
}

// func (param *Parameters) Encode(k *big.Int) uint16 {
// 	K := make([][]uint16, param.m)
// 	for i := range K {
// 		K[i] = make([]uint16, param.n)
// 		for j := range K[i] {
// 			temp := uint16(0)
// 			for l := int(0); l < param.B; l++ {
// 				//temp +=
// 			}
// 			K[i][j] = param.ec(temp)
// 		}
// 	}
// }

func (param *Parameters) ec(k uint16) uint16 {
	B := bits.Len16(k)
	e := param.D - B
	return k * uint16(math.Pow(2, float64(e))) % param.q
}

func cutBitString(str *big.Int, a, b int) *big.Int {
	result, one := big.NewInt(0), big.NewInt(1)
	for i := a; i <= b; i++ {
		result.Lsh(result, 1)
		if str.Bit(i) == 1 {
			result.Add(result, one)
		}
	}
	return result
}

// func (param *Parameters) Decode(K [][]uint16) uint16 {

// }
