package frodo

// KEM interface
type KEM interface {
	EncapsKeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey)     // returns key pair
	Encaps(pk *EncapsPublicKey) (ct *EncapsCipherText, ss []byte) // using pk, returns ct and secret ss
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

// EncapsKeyGen returns encapsulated key pair structure
func (param *Parameters) EncapsKeyGen() (pk *EncapsPublicKey, sk *EncapsSecretKey) {

	pk, sk = new(EncapsPublicKey), new(EncapsSecretKey)

	rLen := 2 * param.no * param.n * param.lenX
	seedSE, z := uniform(param.lseedSE+1), uniform(param.lenz)
	sk.s = uniform(param.lens)

	seedSE[0] = 0x5f
	pk.seedA = param.shake(z, param.lseedA)
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

	sk.pkh = param.shake(pkh, param.lenpkh)
	sk.seedA = pk.seedA
	sk.b = pk.b

	return
}

// Encaps returns encapsulated ciphertext and secret ss using public key
func (param *Parameters) Encaps(pk *EncapsPublicKey) (ct *EncapsCipherText, ss []byte) {

	ct = new(EncapsCipherText)

	rLen := ((param.m*param.no)*2 + param.n*param.m) * param.lenX
	m := uniform(param.lenM)

	var pKey, seedSE []byte
	pKey = append(pKey, pk.seedA...)
	pKey = append(pKey, pk.b...)

	pkh := param.shake(pKey, param.lenpkh)
	pkh = append(pkh, m...)
	seed := param.shake(pkh, param.lseedSE+param.lenk)

	seedSE = append(seedSE, []byte{0x96}...)
	seedSE = append(seedSE, seed[:(param.lseedSE)]...)
	r := param.shake(seedSE, rLen)

	rLen = param.m * param.no * param.lenX
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
	k = append(k, seed[(param.lseedSE):]...)
	temp = append(temp, ct.c1...)
	temp = append(temp, ct.c2...)
	temp = append(temp, k...)

	ss = param.shake(temp, param.lenss)

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

	seed := param.shake(pkh, param.lseedSE+param.lenk)

	seedSE = append(seedSE, []byte{0x96}...)
	seedSE = append(seedSE, seed[:param.lseedSE]...)

	rLen := (2*param.no + param.n) * param.m * param.lenX
	r := param.shake(seedSE, rLen)

	rLen = param.m * param.no * param.lenX
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
		k1 = append(k1, seed[(param.lseedSE):]...)
		res = append(res, k1...)
	} else {
		res = append(res, sk.s...)
	}

	ss = param.shake(res, param.lenss)

	return
}
