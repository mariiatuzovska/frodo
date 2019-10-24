package frodo

// KEM interface
type KEM interface {
	EncapsKeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey)     // returns key pair
	Encaps(pk *EncapsPublicKey) (ct *EncapsCipherText, ss []byte) // returns ct and secret ss
	Decaps(ct *EncapsCipherText, sk *EncapsSecretKey) (ss []byte) // using sk, returns secret ss from ct
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

// EncapsCipherText structure
type EncapsCipherText struct {
	c1 []byte
	c2 []byte
}

// EncapsKeyGen returns key pair structure
func (param *Parameters) EncapsKeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey) {

	pk, sk = new(EncapsPublicKey), new(EncapsSecretKey)

	rLen := param.no * param.n * param.lenX / 4
	seedSE, z := uniform(param.lseedSE/8+1), uniform(param.lenz/8)
	sk.s = uniform(param.lens / 8)

	seedSE[0] = 0x5f
	pk.seedA = param.shake(z, param.lseedA/8)
	r := param.shake(seedSE, rLen)

	A := param.Gen(pk.seedA)

	rLen /= 2
	sk.S = param.SampleMatrix(r[:rLen], param.no, param.n)
	E := param.SampleMatrix(r[rLen:], param.no, param.n)

	B := param.mulAddMatrices(A, sk.S, E)
	pk.b = param.Pack(B)

	var pkh []byte
	pkh = append(pkh, pk.seedA...)
	pkh = append(pkh, pk.b...)

	sk.pkh = param.shake(pkh, param.lenpkh/8)
	sk.seedA = pk.seedA
	sk.b = pk.b

	return
}

// Encaps returns ciphertext and secret ss using public key
func (param *Parameters) Encaps(pk *EncapsPublicKey) (ct *EncapsCipherText, ss []byte) {

	ct = new(EncapsCipherText)

	rLen := ((param.m*param.no)*2 + param.n*param.m) * param.lenX / 8
	m := uniform(param.lenM / 8)

	var pKey, seedSE []byte
	pKey = append(pKey, pk.seedA...)
	pKey = append(pKey, pk.b...)

	pkh := param.shake(pKey, param.lenpkh/8)
	pkh = append(pkh, m...)
	seed := param.shake(pkh, (param.lseedSE+param.lenk)/8)

	seedSE = append(seedSE, []byte{0x96}...)
	seedSE = append(seedSE, seed[:(param.lseedSE/8)]...)
	r := param.shake(seedSE, rLen)

	rLen = param.m * param.no * param.lenX / 8
	S1 := param.SampleMatrix(r[:rLen], param.m, param.no)
	E1 := param.SampleMatrix(r[rLen:2*rLen], param.m, param.no)
	E2 := param.SampleMatrix(r[2*rLen:], param.m, param.n)

	A := param.Gen(pk.seedA)
	B1 := param.mulAddMatrices(S1, A, E1)

	B := param.Unpack(pk.b, param.no, param.n)
	V := param.mulAddMatrices(S1, B, E2)
	C := param.sumMatrices(V, param.Encode(m))

	ct.c1 = param.Pack(B1)
	ct.c2 = param.Pack(C)

	var temp, k []byte
	k = append(k, seed[(param.lseedSE/8):]...)
	temp = append(temp, ct.c1...)
	temp = append(temp, ct.c2...)
	temp = append(temp, k...)

	ss = param.shake(temp, param.lenss/8)

	return
}

// Decaps returns secret ss from ciphertext using secret key
func (param *Parameters) Decaps(ct *EncapsCipherText, sk *EncapsSecretKey) (ss []byte) {

	B1, C := param.Unpack(ct.c1, param.m, param.no), param.Unpack(ct.c2, param.m, param.n)
	B1S := param.mulMatrices(B1, sk.S)

	M := param.subMatrices(C, B1S)
	m1 := param.Decode(M)

	var pkh, seedSE, k1 []byte
	pkh = append(pkh, sk.pkh...)
	pkh = append(pkh, m1...)

	seed := param.shake(pkh, (param.lseedSE+param.lenk)/8)

	seedSE = append(seedSE, []byte{0x96}...)
	seedSE = append(seedSE, seed[:(param.lseedSE/8)]...)

	rLen := (2*param.no + param.n) * param.m * param.lenX / 8
	r := param.shake(seedSE, rLen)

	rLen = param.m * param.no * param.lenX / 8
	S1 := param.SampleMatrix(r[:rLen], param.m, param.no)
	E1 := param.SampleMatrix(r[rLen:2*rLen], param.m, param.no)
	E2 := param.SampleMatrix(r[2*rLen:], param.m, param.n)

	A := param.Gen(sk.seedA)
	B := param.Unpack(sk.b, param.no, param.n)

	B2 := param.mulAddMatrices(S1, A, E1)
	V := param.mulAddMatrices(S1, B, E2)
	C1 := param.sumMatrices(V, param.Encode(m1))

	var res []byte
	res = append(res, ct.c1...)
	res = append(res, ct.c2...)

	if eqMatrices(B1, B2) == true && eqMatrices(C, C1) == true {
		k1 = append(k1, seed[(param.lseedSE/8):]...)
		res = append(res, k1...)
	} else {
		res = append(res, sk.s...)
	}

	ss = param.shake(res, param.lenss/8)

	return
}
