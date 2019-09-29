package frodo

import (
	"log"
	"math/bits"

	"github.com/mariiatuzovska/frodokem/util/bitstr"
	"golang.org/x/crypto/sha3"
)

type Frodo interface { // frodo interface

	Encode(k *bitstr.BitString) [][]uint16                // encodes an integer 0 ≤ k < 2^B as an element in Zq by multiplying it by q/2B = 2^(D−B): ec(k) := k·q/2^B
	Decode(K [][]uint16) *bitstr.BitString                // decodes the m-by-n matrix K into a bit string of length l = B·m·n. dc(c) = ⌊c·2^B/q⌉ mod 2^B
	Pack(C [][]uint16) *bitstr.BitString                  // packs a matrix into a bit string
	Unpack(b *bitstr.BitString, n1, n2 int) [][]uint16    // unpacks a bit string into a matrix
	Gen(seed *bitstr.BitString) [][]uint16                // returns a pseudorandom matrix using SHAKE128
	Sample(t uint16) int                                  // returns a sample e from the distribution χ
	SampleMatrix(r *bitstr.BitString, n1, n2 int) [][]int // sample the n1 * n2 matrix entry

}

type Parameters struct { // parameters

	no      int      // n ≡ 0 (mod 8)
	q       uint32   // a power-of-two integer modulus with exponent D ≤ 16
	D       int      // a power
	m, n    int      // integer matrix dimensions with
	B       int      // the number of bits encoded in each matrix entry
	l       int      // B·m·n, the length of bit strings that are encoded as m-by-n matrices
	lseedA  int      // the bit length of seeds used for pseudorandom matrix generation
	lseedSE int      // the bit length of seeds used for pseudorandom bit generation for error sampling
	lenX    int      // length of χ distribution
	X       []uint16 // a probability distribution on Z, rounded Gaussian distribution
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
	param.lenX = 16
	param.l = 128
	param.X = []uint16{9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1, 0, 0, 0}

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
	param.lenX = 16
	param.l = 128
	param.X = []uint16{11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1, 0, 0, 0, 0, 0}

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
	param.lenX = 16
	param.l = 128
	param.X = []uint16{18286, 14320, 6876, 2023, 364, 40, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	return param
}

func (param *Parameters) Encode(k *bitstr.BitString) [][]uint16 {

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

func (param *Parameters) Decode(K [][]uint16) *bitstr.BitString {

	k := bitstr.New(param.l)
	for i, row := range K {
		for j := range row {
			temp := param.dc(K[i][j])
			for l := 0; l < param.B; l++ {
				if temp&1 == 1 {
					k.SetBit((i*param.n+j)*param.B+l, 1)
				}
				temp >>= 1
			}
		}
	}
	return k
}

func (param *Parameters) Pack(C [][]uint16) *bitstr.BitString {

	b, n2 := bitstr.New(param.D*len(C)*len(C[0])), len(C[0])
	for i, row := range C {
		for j := range row {
			temp := uint16(0x8000)
			for l := 0; l < param.D; l++ {
				if (temp>>uint(l))&C[i][j] != 0 {
					b.SetBit((i*n2+j)*param.D+l, 1)
				}
			}
		}
	}
	return b
}

func (param *Parameters) Unpack(b *bitstr.BitString, n1, n2 int) [][]uint16 {

	C := make([][]uint16, n1)
	for i := range C {
		C[i] = make([]uint16, n2)
		for j := range C[i] {
			temp, k := uint16(0), uint16(0x8000)
			for l := 0; l < param.D; l++ {
				if b.Bit((i*n2+j)*param.D+l) == 1 {
					temp += k
				}
				k >>= 1
			}
			C[i][j] = temp
		}
	}
	return C
}

func (param *Parameters) Gen(seed *bitstr.BitString) [][]uint16 {

	A := make([][]uint16, param.n)
	for i := 0; i < param.n; i++ {
		b, shakeStr := seed.Get2Bytes(i), make([]byte, 2*param.n)
		if param.no == 640 {
			shake := sha3.NewShake128()
			shake.Write(b)
			shake.Read(shakeStr)
		} else {
			shake := sha3.NewShake256()
			shake.Write(b)
			shake.Read(shakeStr)
		}
		A[i] = make([]uint16, param.m)
		for j := 0; j < param.m; j++ {
			u16 := (uint16(shakeStr[j*2]) << 8) + uint16(shakeStr[j*2+1])
			A[i][j] = uint16(uint32(u16) % param.q)
		}
	}
	return A
}

func (param *Parameters) Sample(t uint16) int {

	e, c := 0, int(t&1)
	t >>= 1
	for z := 0; z < param.lenX; z++ {
		if t > param.X[z] && param.X[z] != 0 {
			e++
		}
	}
	if c == 0 {
		c = 1
	} else {
		c = -1
	}
	return c * e
}

func (param *Parameters) SampleMatrix(r *bitstr.BitString, n1, n2 int) [][]int {

	if r.Len()/16 < n1*n2 {
		log.Fatal("Invalid input in SampleMatrix() frodo.go")
	}
	E := make([][]int, n1)
	for i := 0; i < n1; i++ {
		E[i] = make([]int, n2)
		for j := 0; j < n2; j++ {
			t := r.GetUint16(i*n2 + j)
			E[i][j] = param.Sample(t)
		}
	}
	return E
}

func (param *Parameters) ec(k uint16) uint16 {
	t := bits.RotateLeft16(1, param.D-param.B)
	return t * k
}

func (param *Parameters) dc(c uint16) uint16 {
	b, d := bits.RotateLeft16(1, param.B), bits.RotateLeft32(1, param.D-param.B)
	r, _ := bits.Div32(0, uint32(c), d)
	return uint16(r) % b
}
