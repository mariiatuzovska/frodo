package frodo

// KEM interface
type KEM interface {
	KeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey) // key pair generation
}

// EncapsPublicKey internal structure
type EncapsPublicKey struct {
	pkh []byte // {0,1}^(lseedA + D·no·n)
}

// EncapsSecretKey internal structure
type EncapsSecretKey struct {
	b   []byte     // {0,1}^(lens + lseedSE + D·no·n)
	S   [][]uint16 // matrix є Zq (n*no)
	pkh []byte     // {0,1}^lenpkh
}

// EncapsKeyGen returns encapsulated key pairs structures
// func (param *Parameters) EncapsKeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey) {

// 	pk, sk = new(EncapsPublicKey), new(EncapsSecretKey)

// 	s, seedSE, z := make([]byte, param.lens/8), make([]byte, (param.lseedSE/8)+1), make([]byte, param.lenz/8)
// 	rLen := param.no * param.n * param.lenX / 4

// 	seedA, r := make([]byte, param.lseedA/8), make([]byte, rLen)
// 	A := param.Gen(seedA)

// 	rand.Seed(time.Now().UTC().UnixNano())
// 	for i := range s {
// 		s[i] = byte(rand.Intn(256))
// 	}
// 	for i := range seedSE {
// 		seedSE[i] = byte(rand.Intn(256))
// 	}
// 	for i := range z {
// 		z[i] = byte(rand.Intn(256))
// 	}

// 	seedSE[0] = 0x5f
// 	if param.no == 640 {
// 		shake := sha3.NewShake128()
// 		shake.Write(seedSE)
// 		shake.Read(r)
// 	} else {
// 		shake := sha3.NewShake256()
// 		shake.Write(seedSE)
// 		shake.Read(r)
// 	}

// 	rLen /= 2
// 	r1, r2 := make([]byte, rLen), make([]byte, rLen)
// 	for i := range r1 {
// 		r1[i] = r[i]
// 		r2[i] = r[rLen+1]
// 	}

// 	sk.S = param.SampleMatrix(r1, param.no, param.n)
// 	E := param.SampleMatrix(r2, param.no, param.n)

// 	B := param.sumMatrices(param.mulMatrices(A, sk.S), E)
// 	sk.b = param.Pack(B)

// 	pk.pkh = make([]byte, len(seedA)+len(sk.b))
// 	for i := range seedA {
// 		pk.pkh[i] = seedA[i]
// 	}
// 	for i := range sk.b {
// 		pk.pkh[i+len(seedA)] = sk.b[i]
// 	}

// 	sk.pkh = make([]byte, param.lenpkh/8)
// 	if param.no == 640 {
// 		shake := sha3.NewShake128()
// 		shake.Write(pk.pkh)
// 		shake.Read(sk.pkh)
// 	} else {
// 		shake := sha3.NewShake256()
// 		shake.Write(pk.pkh)
// 		shake.Read(sk.pkh)
// 	}
// 	return
// }
