package frodo

// PKE interface
type PKE interface {
	KeyGen() (pk *PublicKey, sk *SecretKey)        // returns key pair sructure
	Enc(message []byte, pk *PublicKey) *CipherText // returns CipherText structure which contains C = (C1, C2)
	Dec(cipher *CipherText, sk *SecretKey) []byte  // returns decrypted with secret key ciphertext
}

// PublicKey structure contains seedA uniform bit string and n-by-m public matrix B є Zq
type PublicKey struct {
	SeedA []byte     // uniform string
	B     [][]uint16 // matrix є Zq
}

// SecretKey structure contains matrix S є Zq
type SecretKey struct {
	S [][]uint16 // matrix є Zq
}

// CipherText structure contains matrices C1 and C2
type CipherText struct {
	C1, C2 [][]uint16
}

// KeyGen genere key pair for chosen parameters
func (param *Parameters) KeyGen() (pk *PublicKey, sk *SecretKey) {

	pk, sk = new(PublicKey), new(SecretKey)
	pk.SeedA = uniform(param.lseedA)
	rLen, seedSE := 2*param.no*param.n*param.lenX, uniform((param.lseedSE)+1)

	seedSE[0] = 0x5F
	r := param.shake(seedSE, rLen)

	rLen /= 2
	A := param.Gen(pk.SeedA)
	sk.S = param.SampleMatrix(r[:rLen], param.no, param.n)
	E := param.SampleMatrix(r[rLen:], param.no, param.n)
	pk.B = param.mulAddMatrices(A, sk.S, E)

	return
}

// Enc encrypts message for chosen parameters, using public key structure
// returns C = (C1, C2); C1 = S1*A + E1,
// C2 = V + M = S1*B + E2 + M = S1*A*S + S1*E + E2 + M
func (param *Parameters) Enc(message []byte, pk *PublicKey) *CipherText {
	seedSE := uniform(param.lseedSE + 1)
	A, rLen := param.Gen(pk.SeedA), (2*param.no+param.n)*param.m*param.lenX

	seedSE[0] = 0x96
	r := param.shake(seedSE, rLen)

	rLen = param.m * param.no * param.lenX
	S1 := param.SampleMatrix(r[:rLen], param.m, param.no)
	E1 := param.SampleMatrix(r[rLen:2*rLen], param.m, param.no)
	E2 := param.SampleMatrix(r[2*rLen:], param.m, param.n)
	V := param.mulAddMatrices(S1, pk.B, E2)

	cipher := new(CipherText)
	cipher.C1 = param.mulAddMatrices(S1, A, E1)             // C1 = S1*A + E1
	cipher.C2 = param.sumMatrices(V, param.Encode(message)) // C2 = V + M = S1*B + E2 + M = S1*A*S + S1*E + E2 + M

	return cipher
}

// Dec returns decrypted with secret key cihertext
// with error S1*E + E2 − E1*S, that cleans up using Decode
// proved by lemma 2.18 [FKEM]
func (param *Parameters) Dec(cipher *CipherText, sk *SecretKey) []byte {

	M := param.subMatrices(cipher.C2, param.mulMatrices(cipher.C1, sk.S)) // M = C2 - C1*S = Enc(message) + S1*E + E2 - E1*S
	message := param.Decode(M)

	return message
}
