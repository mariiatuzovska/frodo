package frodo

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/sha3"
)

// KEM interface
type KEM interface {
	KeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey)                // key pair encapsulation
	Encaps(message []byte, pk *EncapsPublicKey) (ct *EncapsCipherText) // returns encapsulated ct
	Decaps(ct *EncapsCipherText, sk *EncapsSecretKey) (message []byte) // return message
}

// EncapsPublicKey internal structure
type EncapsPublicKey struct {
	seedA []byte // $U({0,1}^lseedA)
	b     []byte // packed matrix B
}

// EncapsSecretKey internal structure
type EncapsSecretKey struct {
	s     []byte     // $U({0,1}^lens)
	seedA []byte     // $U({0,1}^lseedA)
	b     []byte     // packed matrix B
	S     [][]uint16 // matrix є Zq (n*no)
	pkh   []byte     // {0,1}^lenpkh
}

// EncapsCipherText contain encapsulated ct
type EncapsCipherText struct {
	c1 []byte
	c2 []byte
}

// EncapsKeyGen returns encapsulated key pairs structures
func (param *Parameters) EncapsKeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey) {

	pk, sk = new(EncapsPublicKey), new(EncapsSecretKey)

	seedSE, z, rLen := make([]byte, (param.lseedSE/8)+1), make([]byte, param.lenz/8), param.no*param.n*param.lenX/4
	pk.seedA, sk.s = make([]byte, param.lseedA/8), make([]byte, param.lens/8)
	r := make([]byte, rLen)

	rand.Seed(time.Now().UTC().UnixNano())
	for i := range sk.s {
		sk.s[i] = byte(rand.Intn(256))
	}
	for i := range seedSE {
		seedSE[i] = byte(rand.Intn(256))
	}
	for i := range z {
		z[i] = byte(rand.Intn(256))
	}

	seedSE[0] = 0x5f
	if param.no == 640 {
		shake := sha3.NewShake128()
		shake.Write(z)
		shake.Read(pk.seedA)
		shake = sha3.NewShake128()
		shake.Write(seedSE)
		shake.Read(r)
	} else {
		shake := sha3.NewShake256()
		shake.Write(z)
		shake.Read(pk.seedA)
		shake = sha3.NewShake256()
		shake.Write(seedSE)
		shake.Read(r)
	}

	rLen /= 2
	r1, r2 := make([]byte, rLen), make([]byte, rLen)
	for i := range r1 {
		r1[i] = r[i]
		r2[i] = r[rLen+1]
	}

	A := param.Gen(pk.seedA)
	sk.S = param.SampleMatrix(r1, param.no, param.n)
	E := param.SampleMatrix(r2, param.no, param.n)
	B := param.mulAddMatrices(A, sk.S, E)
	pk.b = param.Pack(B)

	pkh := make([]byte, len(pk.seedA)+len(pk.b))
	for i := range pk.seedA {
		pkh[i] = pk.seedA[i]
	}
	for i := range pk.b {
		pkh[i+len(pk.seedA)] = pk.b[i]
	}

	sk.pkh = make([]byte, param.lenpkh/8)
	if param.no == 640 {
		shake := sha3.NewShake128()
		shake.Write(pkh)
		shake.Read(sk.pkh)
	} else {
		shake := sha3.NewShake256()
		shake.Write(pkh)
		shake.Read(sk.pkh)
	}

	sk.seedA = pk.seedA
	sk.b = pk.b

	return
}

//func (param *Parameters) Encaps()
