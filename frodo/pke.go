package frodo

import (
	"math/rand"
	"time"

	"github.com/mariiatuzovska/frodokem/util/bitstr"
	"golang.org/x/crypto/sha3"
)

// PKE interface
type PKE interface {
	KeyGen() (pk *PublicKey, sk *SecretKey) // key pair generation
	Enc(pk *PublicKey) (C1, C2 [][]uint16)  // return encrypted messages
}

// PublicKey internal structure
type PublicKey struct {
	seedA *bitstr.BitString // uniform string
	B     [][]uint16        // matrix є Zq
}

// SecretKey internal structure
type SecretKey struct {
	S [][]uint16 // matrix є Zq
}

// CipherText internal structure
type CipherText struct {
	C1, C2 [][]uint16
}

// KeyGen genere key pairs for chosen parameters
func (param *Parameters) KeyGen() (pk *PublicKey, sk *SecretKey) {

	pk, sk = new(PublicKey), new(SecretKey)
	pk.seedA = bitstr.NewRand(param.lseedA)

	seedSE, r := make([]byte, param.lseedSE+1), make([]byte, param.n*param.m*param.lenX/4)

	seedSE[0] = 0x5F
	rand.Seed(time.Now().UTC().UnixNano())
	for i := 1; i < len(seedSE); i++ {
		seedSE[i] = byte(rand.Intn(256))
	}

	if param.no == 640 {
		shake := sha3.NewShake128()
		shake.Write(seedSE)
		shake.Read(r)
	} else {
		shake := sha3.NewShake256()
		shake.Write(seedSE)
		shake.Read(r)
	}

	r1, r2 := bitstr.New(param.n*param.m*param.lenX), bitstr.New(param.n*param.m*param.lenX)
	r1.SetBytesHalf(r, 0, param.n*param.m*param.lenX/8)
	r2.SetBytesHalf(r, param.n*param.m*param.lenX/8, param.n*param.m*param.lenX/4)

	A := param.Gen(pk.seedA)
	sk.S = param.SampleMatrix(r1, param.n, param.m)
	E := param.SampleMatrix(r2, param.n, param.m)
	AS := param.mulMatrices(A, sk.S)
	pk.B = param.sumMatrices(AS, E)

	return
}

// Enc encrypts message for chosen parameters length
func (param *Parameters) Enc(message *bitstr.BitString, pk *PublicKey) *CipherText {

	A, mn := param.Gen(pk.seedA), param.n*param.m
	seedSE := make([]byte, (((mn * 3 * param.lenX) / 8) + 1))
	r := make([]byte, ((mn * 3 * param.lenX) / 8))

	seedSE[0] = byte(0x96)
	for i := 1; i < len(seedSE); i++ {
		seedSE[i] = byte(rand.Int())
	}

	if param.no == 640 {
		shake := sha3.NewShake128()
		shake.Write(seedSE)
		shake.Read(r)
	} else {
		shake := sha3.NewShake256()
		shake.Write(seedSE)
		shake.Read(r)
	}

	r1, r2, r3 := bitstr.New(mn*param.lenX), bitstr.New(mn*param.lenX), bitstr.New(mn*param.lenX)
	r1.SetBytesHalf(r, 0, mn/8)
	r2.SetBytesHalf(r, mn/8, mn/4)
	r3.SetBytesHalf(r, mn/4, mn*3/8)

	S1, E1 := param.SampleMatrix(r1, param.m, param.n), param.SampleMatrix(r2, param.m, param.n)
	E2 := param.SampleMatrix(r3, param.m, param.n)
	V := param.sumMatrices(param.mulMatrices(S1, pk.B), E2)

	cipher := new(CipherText)
	cipher.C1 = param.sumMatrices(param.mulMatrices(S1, A), E1)
	cipher.C2 = param.sumMatrices(V, param.Encode(message))

	return cipher
}

func (param *Parameters) mulMatrices(A, B [][]uint16) [][]uint16 {

	C := make([][]uint16, len(A[0]))
	for i := 0; i < len(A[0]); i++ {
		C[i] = make([]uint16, len(B))
		for j := 0; j < len(B); j++ {
			temp := uint32(0)
			for k := 0; k < len(A); k++ {
				temp += uint32(A[i][k]) * uint32(B[k][j])
				temp %= param.q
			}
			C[i][j] = uint16(temp)
		}
	}
	return C
}

func (param *Parameters) sumMatrices(A, B [][]uint16) [][]uint16 { // for symmetric matrices

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(A[0]))
		for j := 0; j < len(A[0]); j++ {
			C[i][j] = uint16((uint32(A[i][j]) + uint32(B[i][j])) % param.q)
		}
	}
	return C
}
