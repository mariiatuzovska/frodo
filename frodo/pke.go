package frodo

import (
	"math/rand"

	"github.com/mariiatuzovska/frodokem/util/bitstr"
	"golang.org/x/crypto/sha3"
)

type PKE interface { // PKE interface

	KeyGen() (pk *PublicKey, sk *SecretKey) // Key pair generation

}

type PublicKey struct {
	seedA *bitstr.BitString // uniform string
	B     [][]uint16        // matrix є Zq
}

type SecretKey struct {
	S [][]uint16 // matrix є Zq
}

func (param *Parameters) KeyGen() (pk *PublicKey, sk *SecretKey) {

	seedA, seedSE := bitstr.NewRand(param.lseedA), make([]byte, param.lseedSE+1)
	r := make([]byte, 2*param.n*param.m*param.lenX/8)

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

	A := param.Gen(seedA)
	S := param.SampleMatrix(r1, param.n, param.m)
	E := param.SampleMatrix(r2, param.n, param.m)

	return
}

func mulMatrices(A, B [][]uint16) [][]uint16 {

}
