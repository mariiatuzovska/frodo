package frodo

import (
	"math/rand"

	"github.com/mariiatuzovska/frodokem/util/bitstr"
	"golang.org/x/crypto/sha3"
)

type PKE interface { // PKE interface

	KeyGen() (pk *PublicKey, sk *SecretKey) // key pair generation
	Enc(pk *PublicKey) (C1, C2 [][]uint16)  // return encrypted messages

}

type PublicKey struct { // public key internal structure

	seedA *bitstr.BitString // uniform string
	B     [][]uint16        // matrix є Zq

}

type SecretKey struct { // secret key internal structure

	S [][]uint16 // matrix є Zq

}

func (param *Parameters) KeyGen() (pk *PublicKey, sk *SecretKey) {

	pk, sk = new(PublicKey), new(SecretKey)
	pk.seedA = bitstr.NewRand(param.lseedA)

	seedSE, r := make([]byte, param.lseedSE+1), make([]byte, 2*param.n*param.m*param.lenX/8)

	seedSE[0] = 0x5F
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

	r1 := bitstr.New(param.n * param.m * param.lenX)
	r2 := bitstr.New(param.n * param.m * param.lenX)
	r1.SetBytesHalf(r, 0)
	r2.SetBytesHalf(r, 1)

	A := param.Gen(pk.seedA)
	sk.S = param.SampleMatrix(r1, param.n, param.m)
	E := param.SampleMatrix(r2, param.n, param.m)
	AS := param.mulMatrices(A, sk.S)
	pk.B = param.sumMatrices(AS, E)

	return
}

// func (param *Parameters) Enc(message *bitstr.BitString, pk *PublicKey) (C1, C2 [][]uint16) {

// 	A, seedSE := param.Gen(pk.seedA), bitstr.NewRand(param.lseedSE)
// 	r := make([]byte, (((param.n*param.m*2)+(param.n*param.m*param.lenX))/8)+1)
// 	r[0] = byte(0x96)

// }

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
