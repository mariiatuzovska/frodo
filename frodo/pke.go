package frodo

import (
	"math/rand"
	"time"

	"github.com/mariiatuzovska/frodokem/util/bitstr"
	"golang.org/x/crypto/sha3"
)

// PKE interface
type PKE interface {
	KeyGen() (pk *PublicKey, sk *SecretKey)                  // key pair generation
	Enc(pk *PublicKey) (C1, C2 [][]uint16)                   // return encrypted messages
	Dec(cipher *CipherText, sk *SecretKey) *bitstr.BitString // return decrypted with sekret key cihertext
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

	seedSE, r := make([]byte, (param.lseedSE/8)+1), make([]byte, param.no*param.n*param.lenX/4)

	seedSE[0] = 0x5F
	for i := 1; i < len(seedSE); i++ {
		rand.Seed(time.Now().UTC().UnixNano())
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

	r1, r2 := bitstr.New(param.no*param.n*param.lenX), bitstr.New(param.no*param.n*param.lenX)
	r1.SetBytesHalf(r, 0, param.no*param.n*param.lenX/8)
	r2.SetBytesHalf(r, param.no*param.n*param.lenX/8, param.no*param.n*param.lenX/4)

	A := param.Gen(pk.seedA)
	sk.S = param.SampleMatrix(r1, param.no, param.n)
	E := param.SampleMatrix(r2, param.no, param.n)
	AS := param.mulMatrices(A, sk.S)
	pk.B = param.sumMatrices(AS, E)

	return
}

// Enc encrypts message for chosen parameters length
func (param *Parameters) Enc(message *bitstr.BitString, pk *PublicKey) *CipherText {

	A, mn := param.Gen(pk.seedA), param.n*param.m
	seedSE := make([]byte, ((param.lseedSE / 8) + 1))
	r := make([]byte, ((2*param.m*param.no+mn)*param.lenX)/8)

	seedSE[0] = byte(0x96)
	for i := 1; i < len(seedSE); i++ {
		rand.Seed(time.Now().UTC().UnixNano())
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

	r1, r2, r3 := bitstr.New(param.m*param.no*param.lenX), bitstr.New(param.m*param.no*param.lenX), bitstr.New(mn*param.lenX)
	r1.SetBytesHalf(r, 0, param.m*param.no/8)
	r2.SetBytesHalf(r, param.m*param.no/8, param.m*param.no/4)
	r3.SetBytesHalf(r, param.m*param.no/4, (2*param.m*param.no+mn)/8)

	S1 := param.SampleMatrix(r1, param.m, param.no)
	E1 := param.SampleMatrix(r2, param.m, param.no)
	E2 := param.SampleMatrix(r3, param.m, param.n)
	V := param.sumMatrices(param.mulMatrices(S1, pk.B), E2)

	cipher := new(CipherText)
	cipher.C1 = param.sumMatrices(param.mulMatrices(S1, A), E1)
	cipher.C2 = param.sumMatrices(V, param.Encode(message))

	return cipher
}

// Dec return decrypted with secret key cihertext
func (param *Parameters) Dec(cipher *CipherText, sk *SecretKey) *bitstr.BitString {

	M := param.subMatrices(cipher.C2, param.mulMatrices(cipher.C1, sk.S))
	message := param.Decode(M)
	return message
}

// A (n1*m1); B (n2*m2) => A * B = C (n1*m2)
func (param *Parameters) mulMatrices(A, B [][]uint16) [][]uint16 {

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(B[0]))
		for j := 0; j < len(B[0]); j++ {
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

func (param *Parameters) subMatrices(A, B [][]uint16) [][]uint16 { // for symmetric matrices

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(A[0]))
		for j := 0; j < len(A[0]); j++ {
			C[i][j] = uint16(((param.q | uint32(A[i][j])) - uint32(B[i][j])) % param.q)
		}
	}
	return C
}
