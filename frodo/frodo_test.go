package frodo

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/mariiatuzovska/webapp/frodokem/frodo"
)

func TestEncodeDecode(t *testing.T) {

	rand.Seed(time.Now().UTC().UnixNano())
	m := make([]byte, 128/8)
	for i := range m {
		m[i] = byte(rand.Int())
	}

	frodo640 := frodo.Frodo640()
	fmt.Printf("%x\n", m)
	x1 := frodo640.Encode(m)
	y1 := frodo640.Decode(x1)

	if y1 != m {
		t.Fatal("Wrong encode-decode (frodo.go: 110 & 120) for Frodo640 parameters")
	}

	m = make([]byte, 192/8)
	for i := range m {
		m[i] = byte(rand.Int())
	}

	frodo976 := frodo.Frodo976()
	fmt.Printf("%x\n", m)
	x2 := frodo976.Encode(m)
	y2 := frodo976.Decode(x2)
	fmt.Printf("%x\n", y2)

	if y2 != m {
		t.Fatal("Wrong encode-decode (frodo.go: 110 & 120) for Frodo976 parameters")
	}

	m := make([]byte, 256/8)
	for i := range m {
		m[i] = byte(rand.Int())
	}

	frodo1344 := frodo.Frodo1344()
	fmt.Printf("%x\n", m)
	x3 := frodo1344.Encode(m)
	y3 := frodo1344.Decode(x3)
	fmt.Printf("%x\n", y3)

	if y3 != m {
		t.Fatal("Wrong encode-decode (frodo.go: 110 & 120) for Frodo1344 parameters")
	}
}

func TestSampleMatrix(t *testing.T) {

	frodo := frodo.Frodo640()
	rand.Seed(time.Now().UTC().UnixNano())

	m := make([]byte, 128)
	for i := range m {
		m[i] = byte(rand.Int())
	}
	fmt.Printf("%x\n", m)
	x := frodo.SampleMatrix(m, 8, 8)
	fmt.Printf("%x\n", x)
}

func TestGen(t *testing.T) {

	frodo := frodo.Frodo1344()
	m := make([]byte, 128/8)

	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	fmt.Printf("%x\n", m)

	n := make([][][]uint16, 10)
	for i := 0; i < 10; i++ {
		n[i] = frodo.Gen(m)
	}

	for i := 1; i < 10; i++ {
		for j := 0; j < len(n[i]); j++ {
			for k := 0; k < len(n[i][j]); k++ {
				if n[i][j][k] != n[i-1][j][k] {
					t.Fatal("false frodo.Gen generation from the same seed")
				}
			}
		}
	}

}

func TestKeyGen1344(t *testing.T) {

	frodo := frodo.Frodo1344()
	pk, sk := frodo.KeyGen()

	fmt.Printf("%x\n", pk)
	fmt.Printf("%x\n", sk)

}

func TextEncDec(t *testing.T) {

	frodo := frodo.Frodo976()
	m := make([]byte, 192/8)

	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	pk, sk := frodo.KeyGen()

	c := frodo.Enc(m, pk)
	e := frodo.Dec(c, sk)

	if m != e {
		t.Fatal("input message do not corect encrypted/decrypted")
	}
}

func TestSampleMatrix(t *testing.T) {

	frodo := frodo.Frodo976()
	m := make([]byte, 128)

	rand.Seed(time.Now().UTC().UnixNano())
	for i := range m {
		m[i] = byte(rand.Int())
	}

	fmt.Printf("%x\n", m)

	a := frodo.SampleMatrix(m, 8, 8)
	b := frodo.SampleMatrix(m, 8, 8)

	for i, row := range a {
		for j := range row {
			if a[i][j] != b[i][j] {
				t.Fatal("Wrong work of Sample matrix")
			}
		}
	}
}
