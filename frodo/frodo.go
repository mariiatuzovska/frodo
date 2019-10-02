package frodo

import (
	"log"
	"math/bits"

	"github.com/mariiatuzovska/frodokem/util/bitstr"
	"golang.org/x/crypto/sha3"
)

// Frodo interface
type Frodo interface {
	Encode(k *bitstr.BitString) [][]uint16                   // Encode encodes an integer 0 ≤ k < 2^B as an element in Zq by multiplying it by q/2B = 2^(D−B): ec(k) := k·q/2^B
	Decode(K [][]uint16) *bitstr.BitString                   // Decode decodes the m-by-n matrix K into a bit string of length l = B·m·n. dc(c) = ⌊c·2^B/q⌉ mod 2^B
	Pack(C [][]uint16) *bitstr.BitString                     // Pack packs a matrix into a bit string
	Unpack(b *bitstr.BitString, n1, n2 int) [][]uint16       // Unpack unpacks a bit string into a matrix
	Gen(seed *bitstr.BitString) [][]uint16                   // Gen returns a pseudorandom matrix using SHAKE128
	Sample(t uint16) uint16                                  // Sample returns a sample e from the distribution χ
	SampleMatrix(r *bitstr.BitString, n1, n2 int) [][]uint16 // SampleMatrix sample the n1 * n2 matrix entry
}

// Parameters of frodo KEM mechanism
type Parameters struct {
	no      int      // n ≡ 0 (mod 8) the main parameter
	q       uint32   // a power-of-two integer modulus with exponent D ≤ 16
	D       int      // a power
	m, n    int      // integer matrix dimensions with
	B       int      // the number of bits encoded in each matrix entry
	l       int      // B·m·n, the length of bit strings that are encoded as m-by-n matrices
	lseedA  int      // the bit length of seeds used for pseudorandom matrix generation
	lseedSE int      // the bit length of seeds used for pseudorandom bit generation for error sampling
	lenX    int      // length of χ distribution
	X       []uint16 // a probability distribution on Z, rounded Gaussian distribution
	lenM    int      // bit length of message
}

// Frodo640 returns Parameters struct no.640
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
	param.lenM = 128
	param.lenX = 16
	param.l = 128
	param.X = []uint16{9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1}

	return param
}

// Frodo976 returns Parameters struct no.976
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
	param.lenM = 128
	param.lenX = 16
	param.l = 128
	param.X = []uint16{11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1}

	return param
}

// Frodo1344 returns Parameters struct no.1344
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
	param.lenM = 128
	param.lenX = 16
	param.l = 128
	param.X = []uint16{18286, 14320, 6876, 2023, 364, 40, 2}

	return param
}

// Encode encodes an integer 0 ≤ k < 2^B as an element in Zq by multiplying it by q/2B = 2^(D−B): ec(k) := k·q/2^B
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

// Decode decodes the m-by-n matrix K into a bit string of length l = B·m·n. dc(c) = ⌊c·2^B/q⌉ mod 2^B
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

// Pack packs a matrix into a bit string
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

// Unpack unpacks a bit string into a matrix
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

// Gen returns a pseudorandom matrix using SHAKE128
func (param *Parameters) Gen(seed *bitstr.BitString) [][]uint16 {

	A := make([][]uint16, param.no)
	for i := uint16(0); i < uint16(param.no); i++ {
		seedA, shakeStr := seed, make([]byte, param.no*2)
		seedA.ConcatUint16(i)
		b := seedA.GetBytes()
		A[i] = make([]uint16, param.no)

		if param.no == 640 {
			shake := sha3.NewShake128()
			shake.Write(b)
			shake.Read(shakeStr)
		} else {
			shake := sha3.NewShake256()
			shake.Write(b)
			shake.Read(shakeStr)
		}

		for j := 0; j < param.no; j++ {
			A[i][j] = (uint16(shakeStr[j*2]) << 8) | uint16(shakeStr[i*2+1])
		}
	}

	return A
}

// Sample returns a sample e from the distribution χ
func (param *Parameters) Sample(r uint16) uint16 {

	e, c, t := uint16(0), r&1, r>>1
	for z := range param.X {
		if t > param.X[z] {
			e++
		}
	}
	if c != 0 {
		e = uint16(param.q - uint32(e))
	}
	return e
}

// SampleMatrix sample the n1 * n2 matrix entry
func (param *Parameters) SampleMatrix(r *bitstr.BitString, n1, n2 int) [][]uint16 {

	if r.Len()/16 < n1*n2 {
		log.Fatal("Invalid input in SampleMatrix() frodo.go")
	}
	E := make([][]uint16, n1)
	for i := 0; i < n1; i++ {
		E[i] = make([]uint16, n2)
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
