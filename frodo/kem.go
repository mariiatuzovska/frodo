package frodo

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/sha3"
)

// KEM interface containts encasulation of key pairs, ciphertexts
type KEM interface {
	KeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey)                // key pair encapsulation
	Encaps(message []byte, pk *EncapsPublicKey) (ct *EncapsCipherText) // returns encapsulated ct
	Decaps(ct *EncapsCipherText, sk *EncapsSecretKey) (message []byte) // return message
}

// EncapsPublicKey structure
type EncapsPublicKey struct {
	seedA []byte // $U({0,1}^lseedA)
	b     []byte // packed matrix B
}

// EncapsSecretKey structure
type EncapsSecretKey struct {
	s     []byte     // $U({0,1}^lens)
	seedA []byte     // $U({0,1}^lseedA)
	b     []byte     // packed matrix B
	S     [][]uint16 // matrix є Zq (n*no)
	pkh   []byte     // {0,1}^lenpkh
}

// EncapsCipherText contain encapsulated ciphertext
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

// Encaps returns 
func (param *Parameters) Encaps(message []byte, pk *EncapsPublicKey) (ct *EncapsCipherText) {

	ct = new(EncapsCipherText)
	m, temp := make([]byte, param.lenM/8), make([]byte, len(pk.seedA)+len(pk.b))
	seed, pkh := make([]byte, (param.lseedSE+param.lenk)/8), make([]byte, (param.lenpkh)/8)
	r := make([]byte, ((para.m * param.no) * 2 + param.n * param.m)*param.lenX/8)
	seedSE, k := make([]byte, param.lseedSE/8 + 1), make([]byte, param.lenk/8)

	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Intn(256))
	}
	for i := range pk.seedA {
		temp[i] = pk.seedA[i]
	}
	for i := range pk.b {
		temp[i+len(pk.seedA)] = pk.b[i]
	}

	if param.no = 640 {
		shake := sha3.NewShake128()
		shake.Write(temp)
		shake.Read(pkh)
	} else {
		shake := sha3.NewShake256()
		shake.Write(temp)
		shake.Read(pkh)
	}

	temp = new(make([]byte, len(pkh) + len(m)))
	for i := range pkh {
		temp[i] = pkh[i]
	}
	for i := range m {
		temp[i + len(pkh)] = pkh[i]
	}

	if param.no = 640 {
		shake := sha3.NewShake128()
		shake.Write(temp)
		shake.Read(seed)
	} else {
		shake := sha3.NewShake256()
		shake.Write(temp)
		shake.Read(seed)
	}

	seedSE[0] = 0x96
	for i := 1; i < len(seedSE); i++ {
		seedSE[i] = seed[i - 1]
	}
	for i := range k {
		k[i] = seed[len(seedSE) - 1 + 1]
	}

	if param.no = 640 {
		shake := sha3.NewShake128()
		shake.Write(seedSE)
		shake.Read(r)
	} else {
		shake := sha3.NewShake256()
		shake.Write(seedSE)
		shake.Read(r)
	}

	r1, r2 := make([]byte, param.m*param.no*parm.lenX/8), make([]byte, param.m*param.no*parm.lenX/8)
	r3 := make([]byte, param.m*param.n*parm.lenX/8)

	for i := range r1 {
		r1[i] = r[i]
		r2[i] = r[i + len(r1)]
	}
	for i := range r1 {
		r3[i] = r[i + len(r1) * 2]
	}

	S1 := param.SampleMatrix(r1, param.m, param.no)
	E1 := param.SampleMatrix(r2, param.m, param.no)
	E2 := param.SampleMatrix(r1, param.m, param.n)
	A := param.Gen(pk.seedA)
	B1 := param.mulAddMatrices(S1, A, E1)
	B := param.Unpack(pk.b, param.no, param.n)
	V := param.mulAddMatrices(S1, B, E2)
	C := param.sumMatrices(V, param.Encode(m))

	ct.c1 = param.Pack(B1)
	ct.c2 = param.Pack(C)

	temp = new(make([]byte, len(ct.c1) + len(ct.c2) + len(k)))
	for i := range ct.c1 {
		temp[i] = ct.c1[i]
	}
	for i := range ct.c2 {
		temp[i + len(ct.c1)] = ct.c2[i]
	}
	for i := range k {
		temp[i + len(ct.c1) + len(ct.c2)] = k[i]
	}

	ct.ss = make([]byte, param.lenss/8)
	if param.no = 640 {
		shake := sha3.NewShake128()
		shake.Write(temp)
		shake.Read(ct.ss)
	} else {
		shake := sha3.NewShake256()
		shake.Write(temp)
		shake.Read(ct.ss)
	}

	return
}

