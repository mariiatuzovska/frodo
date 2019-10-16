package frodo

// PKE interface
type PKE interface {
	KeyGen() (pk *PublicKey, sk *SecretKey)       // key pair generation
	Enc(pk *PublicKey) (C1, C2 [][]uint16)        // return encrypted messages
	Dec(cipher *CipherText, sk *SecretKey) []byte // return decrypted with sekret key cihertext
}

// PublicKey structure
type PublicKey struct {
	seedA []byte     // uniform string
	B     [][]uint16 // matrix є Zq
}

// SecretKey structure
type SecretKey struct {
	S [][]uint16 // matrix є Zq
}

// CipherText structure
type CipherText struct {
	C1, C2 [][]uint16
}

// KeyGen genere key pairs for chosen parameters
func (param *Parameters) KeyGen() (pk *PublicKey, sk *SecretKey) {

	pk, sk = new(PublicKey), new(SecretKey)
	pk.seedA = uniform(param.lseedA/8)
	rLen, seedSE := param.no * param.n * param.lenX / 4, uniform((param.lseedSE/8)+1)

	seedSE[0] = 0x5F
	r := param.shake(seedSE, rLen)

	rLen /= 2
	A := param.Gen(pk.seedA)
	sk.S = param.SampleMatrix(r[:rLen], param.no, param.n)
	E := param.SampleMatrix(r[rLen:], param.no, param.n)
	pk.B = param.mulAddMatrices(A, sk.S, E)

	return
}

// Enc encrypts message for chosen parameters
func (param *Parameters) Enc(message []byte, pk *PublicKey) *CipherText {

	A, rLen := param.Gen(pk.seedA), (2*param.m*param.no+param.n*param.m)*param.lenX/8
	seedSE := uniform(param.lseedSE / 8 + 1)

	seedSE[0] = 0x96
	r := param.shake(seedSE, rLen)

	rLen = param.m * param.no * param.lenX / 8
	S1 := param.SampleMatrix(r[:rLen], param.m, param.no)
	E1 := param.SampleMatrix(r[rLen:2*rLen], param.m, param.no)
	E2 := param.SampleMatrix(r[2*rLen:], param.m, param.n)
	V := param.mulAddMatrices(S1, pk.B, E2)

	cipher := new(CipherText)
	cipher.C1 = param.mulAddMatrices(S1, A, E1)             // C1 = S1*A + E1
	cipher.C2 = param.sumMatrices(V, param.Encode(message)) // C2 = V + M = S1*B + E2 + M = S1*A*S + S1*E + E2 + M

	return cipher
}

// Dec return decrypted with secret key cihertext
// with error S1*E + E2 − E1*S.
func (param *Parameters) Dec(cipher *CipherText, sk *SecretKey) []byte {

	M := param.subMatrices(cipher.C2, param.mulMatrices(cipher.C1, sk.S)) // M = C2 - C1*S = Enc(message) + S1*E + E2 - E1*S
	message := param.Decode(M)

	return message
}
