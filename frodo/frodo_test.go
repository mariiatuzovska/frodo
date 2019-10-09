package frodo

import (
	"math/rand"
	"testing"
	"time"

	"github.com/mariiatuzovska/webapp/frodokem/frodo"
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
	return nil
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
	return nil
}

func TestFrodo1344(t *testing.T) {

	frodo := frodo.Frodo976()

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
	return nil
}
