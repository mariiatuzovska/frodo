package frodo

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/sha3"
)

// PKE interface
type PKE interface {
	KeyGen() (pk *PublicKey, sk *SecretKey)       // key pair generation
	Enc(pk *PublicKey) (C1, C2 [][]uint16)        // return encrypted messages
	Dec(cipher *CipherText, sk *SecretKey) []byte // return decrypted with sekret key cihertext
}

// PublicKey internal structure
type PublicKey struct {
	seedA []byte     // uniform string
	B     [][]uint16 // matrix є Zq
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
	rLen := param.no * param.n * param.lenX / 4
	pk.seedA = make([]byte, param.lseedA/8)
	seedSE, r := make([]byte, (param.lseedSE/8)+1), make([]byte, rLen)

	rand.Seed(time.Now().UTC().UnixNano())
	for i := range pk.seedA {
		pk.seedA[i] = byte(rand.Intn(256))
	}

	seedSE[0] = 0x5F
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

	rLen /= 2
	r1, r2 := make([]byte, rLen), make([]byte, rLen)
	for i := range r1 {
		r1[i] = r[i]
		r2[i] = r[rLen+i]
	}

	A := param.Gen(pk.seedA)
	sk.S = param.SampleMatrix(r1, param.no, param.n)
	E := param.SampleMatrix(r2, param.no, param.n)
	AS := param.mulMatrices(A, sk.S)
	pk.B = param.sumMatrices(AS, E)

	return
}

// Enc encrypts message for chosen parameters length
func (param *Parameters) Enc(message []byte, pk *PublicKey) *CipherText {

	A, mn := param.Gen(pk.seedA), param.n*param.m
	seedSE := make([]byte, ((param.lseedSE / 8) + 1))
	r := make([]byte, ((2*param.m*param.no+mn)*param.lenX)/8)

	seedSE[0] = 0x96
	rand.Seed(time.Now().UTC().UnixNano())
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

	rLen := param.m * param.no * param.lenX / 8
	r1, r2, r3 := make([]byte, rLen), make([]byte, rLen), make([]byte, mn*param.lenX/8)
	for i := range r1 {
		r1[i] = r[i]
		r2[i] = r[rLen+i]
	}
	rLen += rLen
	for i := range r3 {
		r3[i] = r[rLen+i]
	}

	S1 := param.SampleMatrix(r1, param.m, param.no)
	E1 := param.SampleMatrix(r2, param.m, param.no)
	E2 := param.SampleMatrix(r3, param.m, param.n)
	V := param.sumMatrices(param.mulMatrices(S1, pk.B), E2)

	cipher := new(CipherText)
	cipher.C1 = param.sumMatrices(param.mulMatrices(S1, A), E1) // C1 = S1*A + E1
	cipher.C2 = param.sumMatrices(V, param.Encode(message))     // C2 = V + M = S1*B + E2 + M = S1*A*S + S1E + E2 + M

	return cipher
}

// Dec return decrypted with secret key cihertext
// with error S1*E + E2 − E1*S.
func (param *Parameters) Dec(cipher *CipherText, sk *SecretKey) []byte {

	M := param.subMatrices(cipher.C2, param.mulMatrices(cipher.C1, sk.S)) // M = C2 - C1*S = Enc(message) + S1*E + E2 - E1*S
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
				temp += (uint32(A[i][k]) * uint32(B[k][j])) % param.q
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
