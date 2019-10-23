package frodo_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/mariiatuzovska/frodokem/frodo"
)

// testing encryption & decryption
// frodo pkg pke.go

func TestFrodoEncDec640(t *testing.T) {

	frodo := frodo.Frodo640()

	m := make([]byte, 128/8)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	pk, sk := frodo.KeyGen()

	c := frodo.Enc(m, pk)
	e := frodo.Dec(c, sk)

	E := frodo.Encode(e)
	M := frodo.Encode(m)

	for i := 0; i < len(M); i++ {
		for j := 0; j < len(M[0]); j++ {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestFrodoEncDec640: expected message\n", m, "\ngot\n", e)
			}
		}
	}
}

func TestFrodoEncDec976(t *testing.T) {

	frodo := frodo.Frodo976()

	m := make([]byte, 192/8)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	pk, sk := frodo.KeyGen()

	c := frodo.Enc(m, pk)
	e := frodo.Dec(c, sk)

	E := frodo.Encode(e)
	M := frodo.Encode(m)

	for i := 0; i < len(M); i++ {
		for j := 0; j < len(M[0]); j++ {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestFrodoEncDec976: expected message\n", m, "\ngot\n", e)
			}
		}
	}
}

func TestFrodoEncDec1344(t *testing.T) {

	frodo := frodo.Frodo1344()

	m := make([]byte, 256/8)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	pk, sk := frodo.KeyGen()

	c := frodo.Enc(m, pk)
	e := frodo.Dec(c, sk)

	E := frodo.Encode(e)
	M := frodo.Encode(m)

	for i := 0; i < len(M); i++ {
		for j := 0; j < len(M[0]); j++ {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestFrodoEncDec1344: expected message\n", m, "\ngot\n", e)
			}
		}
	}
}

// testing frodo KEM
// frodo pkg kem.go

func TestFrodoKEM640(t *testing.T) {

	frodo := frodo.Frodo640()

	pk, sk := frodo.EncapsKeyGen()
	ct, ss := frodo.Encaps(pk)
	s2 := frodo.Decaps(ct, sk)

	for i := range ss {
		if ss[i] != s2[i] {
			t.Error("frodo_test.go/TestFrodoKEM640: expected secret:", ss[i], "but has got", s2[i], "at index", i)
		}
	}
}

func TestFrodoKEM976(t *testing.T) {

	frodo := frodo.Frodo976()

	pk, sk := frodo.EncapsKeyGen()
	ct, ss := frodo.Encaps(pk)
	s2 := frodo.Decaps(ct, sk)

	for i := range ss {
		if ss[i] != s2[i] {
			t.Error("frodo_test.go/TestFrodoKEM976: expected secret", ss[i], "but has got", s2[i], "at index", i)
		}
	}
}

func TestFrodoKEM1344(t *testing.T) {

	frodo := frodo.Frodo1344()

	pk, sk := frodo.EncapsKeyGen()
	ct, ss := frodo.Encaps(pk)
	s2 := frodo.Decaps(ct, sk)

	for i := range ss {
		if ss[i] != s2[i] {
			t.Error("frodo_test.go/TestFrodoKEM1344: expected secret", ss[i], "but has got", s2[i], "at index", i)
		}
	}
}

// testing encode & decode
// frodo pkg frodo.go

func TestEncodeDecode640(t *testing.T) {

	frodo := frodo.Frodo640()

	m := make([]byte, 128/8)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	M := frodo.Encode(m)
	e := frodo.Decode(M)

	for i := range m {
		if m[i] != e[i] {
			t.Error("frodo_test.go/TestEncodeDecode640: xpected secret", m[i], "but has got", e[i], "at index", i)
		}
	}
}

func TestEncodeDecode976(t *testing.T) {

	frodo := frodo.Frodo976()

	m := make([]byte, 192/8)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	M := frodo.Encode(m)
	e := frodo.Decode(M)

	for i := range m {
		if m[i] != e[i] {
			t.Error("frodo_test.go/TestEncodeDecode976: expected secret", m[i], "but has got", e[i], "at index", i)
		}
	}
}

func TestEncodeDecode1344(t *testing.T) {

	frodo := frodo.Frodo1344()

	m := make([]byte, 256/8)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	M := frodo.Encode(m)
	e := frodo.Decode(M)

	for i := range m {
		if m[i] != e[i] {
			t.Error("frodo_test.go/TestEncodeDecode1344: expected secret", m[i], "but has got", e[i], "at index", i)
		}
	}
}

// testing puch & unpack
// frodo pkg frodo.go

func TestUnpakPack640(t *testing.T) {

	frodo := frodo.Frodo640()

	m := make([]byte, 8*15) // {0,1}^(D*n1*n2);  n1 = n2 = 8
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	M := frodo.Unpack(m, 8, 8)
	e := frodo.Pack(M)

	for i := range m {
		if m[i] != e[i] {
			t.Error("frodo_test.go/TestUnpakPack640: expected secret", m[i], "but has got", e[i], "at index", i)
		}
	}
}

func TestUnpakPack976(t *testing.T) {

	frodo := frodo.Frodo976()

	m := make([]byte, 8*16) // {0,1}^(D*n1*n2);  n1 = n2 = 8
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	M := frodo.Unpack(m, 8, 8)
	e := frodo.Pack(M)

	for i := range m {
		if m[i] != e[i] {
			t.Error("frodo_test.go/TestUnpakPack976: expected secret", m[i], "but has got", e[i], "at index", i)
		}
	}
}

func TestUnpakPack1344(t *testing.T) {

	frodo := frodo.Frodo1344()

	m := make([]byte, 8*16) // {0,1}^(D*n1*n2);  n1 = n2 = 8
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	M := frodo.Unpack(m, 8, 8)
	e := frodo.Pack(M)

	for i := range m {
		if m[i] != e[i] {
			t.Error("frodo_test.go/TestUnpakPack1344: expected secret", m[i], "but has got", e[i], "at index", i)
		}
	}
}

// testing Gen
// frodo pkg frodo.go
// from eq seeds it should be eq matrices

func TestGen640(t *testing.T) {

	frodo := frodo.Frodo640()

	m, e := make([]byte, 16), make([]byte, 16)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
		e[i] = m[i]
	}

	M, E := frodo.Gen(m), frodo.Gen(e)

	for i := range M {
		for j := range M[i] {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestUnpakPack640: expected secret", M[i][j], "but has got", E[i][j], "at index", i)
			}
		}
	}
}

func TestGen976(t *testing.T) {

	frodo := frodo.Frodo976()

	m, e := make([]byte, 24), make([]byte, 24)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
		e[i] = m[i]
	}

	M, E := frodo.Gen(m), frodo.Gen(e)

	for i := range M {
		for j := range M[i] {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestUnpakPack976: expected secret", M[i][j], "but has got", E[i][j], "at index", i)
			}
		}
	}
}

func TestGen1344(t *testing.T) {

	frodo := frodo.Frodo1344()

	m, e := make([]byte, 32), make([]byte, 32)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
		e[i] = m[i]
	}

	M, E := frodo.Gen(m), frodo.Gen(e)

	for i := range M {
		for j := range M[i] {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestUnpakPack1344: expected secret", M[i][j], "but has got", E[i][j], "at index", i)
			}
		}
	}
}

// testing Error matrices
// frodo pkg frodo.go
// from eq seeds it should be eq matrices

func TestSample640(t *testing.T) {

	frodo, rLen := frodo.Frodo640(), 640*8*2

	m, e := make([]byte, rLen), make([]byte, rLen)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
		e[i] = m[i]
	}

	M, E := frodo.SampleMatrix(m, 640, 8), frodo.SampleMatrix(e, 640, 8)

	for i := range M {
		for j := range M[i] {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestSample640: expected secret", M[i][j], "but has got", E[i][j], "at index", i)
			}
		}
	}
}

func TestSample976(t *testing.T) {

	frodo, rLen := frodo.Frodo976(), 976*8*2

	m, e := make([]byte, rLen), make([]byte, rLen)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
		e[i] = m[i]
	}

	M, E := frodo.SampleMatrix(m, 976, 8), frodo.SampleMatrix(e, 976, 8)

	for i := range M {
		for j := range M[i] {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestSample976: expected secret", M[i][j], "but has got", E[i][j], "at index", i)
			}
		}
	}
}

func TestSample1344(t *testing.T) {

	frodo, rLen := frodo.Frodo1344(), 1344*8*2

	m, e := make([]byte, rLen), make([]byte, rLen)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
		e[i] = m[i]
	}

	M, E := frodo.SampleMatrix(m, 1344, 8), frodo.SampleMatrix(e, 1344, 8)

	for i := range M {
		for j := range M[i] {
			if M[i][j] != E[i][j] {
				t.Error("frodo_test.go/TestSample1344: expected secret", M[i][j], "but has got", E[i][j], "at index", i)
			}
		}
	}
}
