package frodo_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/mariiatuzovska/frodokem/frodo"
)

func TestFrodo640(t *testing.T) {

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
				t.Error("Expected message\n", m, "\ngot\n", e)
			}
		}
	}
}

func TestFrodo976(t *testing.T) {

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
				t.Error("Expected message\n", m, "\ngot\n", e)
			}
		}
	}
}

func TestFrodo1344(t *testing.T) {

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
				t.Error("Expected message\n", m, "\ngot\n", e)
			}
		}
	}
}

func TestKEMFrodo640(t *testing.T) {

	frodo := frodo.Frodo640()

	pk, sk := frodo.EncapsKeyGen()
	ct, ss := frodo.Encaps(pk)
	s2 := frodo.Decaps(ct, sk)

	for i := range ss {
		if ss[i] != s2[i] {
			t.Error("Expected secret\n", ss, "\nbut has got\n", s2)
		}
	}
}

func TestKEMFrodo976(t *testing.T) {

	frodo := frodo.Frodo976()

	pk, sk := frodo.EncapsKeyGen()
	ct, ss := frodo.Encaps(pk)
	s2 := frodo.Decaps(ct, sk)

	for i := range ss {
		if ss[i] != s2[i] {
			t.Error("Expected secret\n", ss, "\nbut has got\n", s2)
		}
	}
}

func TestKEMFrodo1344(t *testing.T) {

	frodo := frodo.Frodo1344()

	pk, sk := frodo.EncapsKeyGen()
	ct, ss := frodo.Encaps(pk)
	s2 := frodo.Decaps(ct, sk)

	for i := range ss {
		if ss[i] != s2[i] {
			t.Error("Expected secret\n", ss, "\nbut has got\n", s2)
		}
	}
}
