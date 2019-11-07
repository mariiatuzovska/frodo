package frodo

// Frodo interface
type Frodo interface {
	Encode(k []byte) [][]uint16                   // Encode encodes an integer 0 ≤ k < 2^B as an element in Zq by multiplying it by q/2B = 2^(D−B): ec(k) := k·q/2^B
	Decode(K [][]uint16) []byte                   // Decode decodes the m-by-n matrix K into a bit string of length l = B·m·n. dc(c) = ⌊c·2^B/q⌉ mod 2^B
	Pack(C [][]uint16) []byte                     // Pack packs a matrix into a bit string
	Unpack(b []byte, n1, n2 int) [][]uint16       // Unpack unpacks a bit string into a matrix n1-by-n2
	Gen(seed []byte) [][]uint16                   // Gen returns a pseudorandom matrix using SHAKE128
	Sample(t uint16) uint16                       // Sample returns a sample e from the distribution χ
	SampleMatrix(r []byte, n1, n2 int) [][]uint16 // SampleMatrix sample the n1-by-n2 matrix entry
}

// Parameters of frodo KEM mechanism
type Parameters struct {
	no      int      		// n ≡ 0 (mod 8) the main parameter
	q       uint16   		// a power-of-two integer modulus with exponent D ≤ 16 !! minus one for bit masking
	D       int      		// a power 
	m, n    int      		// integer matrix dimensions with
	B       int      		// the number of bits encoded in each matrix entry
	l       int      		// B·m·n, the length of bit strings that are encoded as m-by-n matrices
	lseedA  int      		// the byte length of seed used for pseudorandom pk-matrix generation
	lseedSE int      		// the byte length of seed used for pseudorandom bit generation for error sampling
	lens, lenz, lenpkh int  // the byte length of seeds used for generating key pairs (KEM)
	lenk    int      		// the byte length of seed used for generating seedSE in Encaps (KEM)
	lenss   int      		// the byte length of secret ss (KEM)
	lenX    int      		// the byte length of χ distribution
	X       []uint16 		// a probability distribution on Z, rounded Gaussian distribution
	lenM    int      		// byte length of message
}

// Frodo640 returns Parameters struct no.640
func Frodo640() *Parameters {

	param := new(Parameters)

	param.no = 640
	param.q = 0x7fff
	param.D = 15
	param.B = 2
	param.m = 8
	param.n = 8
	param.lseedA = 16 
	param.lseedSE = 16
	param.lenM = 16
	param.lens = 16
	param.lenk = 16
	param.lenz = 16
	param.lenpkh = 16
	param.lenss = 16
	param.lenX = 2
	param.l = 16
	param.X = []uint16{4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767}

	return param
}

// Frodo976 returns Parameters struct no.976
func Frodo976() *Parameters {

	param := new(Parameters)

	param.no = 976
	param.q = 0xffff
	param.D = 16
	param.B = 3
	param.m = 8
	param.n = 8
	param.lseedA = 16
	param.lseedSE = 24
	param.lenM = 24
	param.lens = 24
	param.lenk = 24
	param.lenz = 24
	param.lenpkh = 24
	param.lenss = 24
	param.lenX = 2
	param.l = 24
	param.X = []uint16{5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767}

	return param
}

// Frodo1344 returns Parameters struct no.1344
func Frodo1344() *Parameters {

	param := new(Parameters)

	param.no = 1344
	param.q = 0xffff
	param.D = 16
	param.B = 4
	param.m = 8
	param.n = 8
	param.lseedA = 16
	param.lseedSE = 32
	param.lenM = 32
	param.lens = 32
	param.lenk = 32
	param.lenz = 32
	param.lenpkh = 32
	param.lenss = 32
	param.lenX = 2
	param.l = 32
	param.X = []uint16{9142, 23462, 30338, 32361, 32725, 32765, 32767}

	return param
}

// Encode encodes an integer 0 ≤ k < 2^B as an element in Zq 
// by multiplying it by q/2B = 2^(D−B): ec(k) := k·q/2^B
func (param *Parameters) Encode(k []byte) [][]uint16 {

	K := make([][]uint16, param.m)
	for i := range K {
		K[i] = make([]uint16, param.n)
		for j := range K[i] {
			temp := uint16(0)
			for l := 0; l < param.B; l++ {
				index, shift := ((i*param.n+j)*param.B+l)/8, uint(((i*param.n+j)*param.B+l)&7)
				if k[index]&(byte(0x80)>>shift) != 0 { // litte-endian
					temp |= uint16(1 << uint(l))
				}
			}
			K[i][j] = param.ec(temp)
		}
	}
	return K
}

// Decode decodes the m-by-n matrix K into a bit string of {0,1}^(B·m·n). dc(c) = ⌊c·2^B/q⌉ mod 2^B
func (param *Parameters) Decode(K [][]uint16) []byte {

	k := make([]byte, param.l)
	for i, row := range K {
		for j := range row {
			temp := param.dc(K[i][j])
			for l := 0; l < param.B; l++ {
				if temp&uint16(1<<uint(l)) != 0 {
					index, shift := ((i*param.n+j)*param.B+l)/8, uint(((i*param.n+j)*param.B+l)&7)
					k[index] |= byte(0x80) >> shift // litte-endian
				}
			}
		}
	}
	return k
}

// Pack packs a n1-by-n2 matrix over Zq into a bit string {0,1}^(D*n1*n2)
func (param *Parameters) Pack(C [][]uint16) []byte {

	n1, n2 := len(C), len(C[0])
	b := make([]byte, param.D*n1*n2/8)
	for i := 0; i < n1; i++ {
		for j := 0; j < n2; j++ {
			for l := 0; l < param.D; l++ {
				if (uint16(1)<<uint(param.D-1-l))&C[i][j] != 0 {
					index, shift := ((i*n2+j)*param.D+l)/8, uint(((i*n2+j)*param.D+l)&7)
					b[index] |= byte(0x80) >> shift
				}
			}
		}
	}
	return b
}

// Unpack unpacks a bit string {0,1}^(D*n1*n2) into a matrix (n1-by-n2) over Zq
func (param *Parameters) Unpack(b []byte, n1, n2 int) [][]uint16 {

	C := make([][]uint16, n1)
	for i := range C {
		C[i] = make([]uint16, n2)
		for j := range C[i] {
			for l := 0; l < param.D; l++ {
				index, shift := ((i*n2+j)*param.D+l)/8, uint(((i*n2+j)*param.D+l)&7)
				if b[index]&byte(0x80>>shift) != 0 {
					C[i][j] |= uint16(1) << uint(param.D-1-l)
				}
			}
		}
	}
	return C
}

// Gen returns a pseudorandom matrix using SHAKE128
func (param *Parameters) Gen(seed []byte) [][]uint16 {

	A := make([][]uint16, param.no)
	for i := uint16(0); i < uint16(param.no); i++ {

		b := []byte{byte(i >> 8), byte(i)}
		b = append(b, seed...)
		shakeStr := param.shake(b, param.no*2)

		A[i] = make([]uint16, param.no)
		for j := 0; j < param.no; j++ {
			A[i][j] = ((uint16(shakeStr[j*2]) << 8) | uint16(shakeStr[i*2+1])) & param.q
		}
	}

	return A
}

// Sample returns a sample e from the distribution χ
func (param *Parameters) Sample(r uint16) uint16 {

	e, t := uint16(0), r>>1
	for z := 0; z < len(param.X)-1; z++ {
		if t > param.X[z] {
			e++
		}
	}
	if r&1 != 0 && e != 0 {
		e = (param.q - e + 1)
	}
	return e
}

// SampleMatrix sample the n1-by-n2 matrix entry
func (param *Parameters) SampleMatrix(r []byte, n1, n2 int) [][]uint16 {

	E := make([][]uint16, n1)
	for i := 0; i < n1; i++ {
		E[i] = make([]uint16, n2)
		for j := 0; j < n2; j++ {
			index := (i*n2 + j) * 2
			E[i][j] = param.Sample((uint16(r[index]) << 8) | uint16(r[index+1]))
		}
	}
	return E
}
