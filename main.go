package main

import (
	"flag"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/mariiatuzovska/frodo"
)

var (
	cpu    = flag.Bool("cpu", false, "Write CPU profile")
	memory = flag.Bool("mem", false, "Write memory profile")
	pke    = flag.Bool("pke", false, "PKE analysis")
	kem    = flag.Bool("kem", false, "KEM analysis")
	no640  = flag.Bool("640", false, "Frodo parameters set no. 640")
	no976  = flag.Bool("976", false, "Frodo parameters set no. 976")
	no1344 = flag.Bool("1344", false, "Frodo parameters set no. 1344")
)

func main() {

	flag.Parse()

	if *cpu {
		f, err := os.Create("./cpu-profile.pb.gz")
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
		leakyFunction()
		return
	}

	go leakyFunction()
	time.Sleep(300 * time.Millisecond)

	if *memory {
		f, err := os.Create("./mem-profile.pb.gz")
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close()
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}

func leakyFunction() {
	if *pke {
		if *no640 {
			PKEFrodo640()
		}
		if *no976 {
			PKEFrodo976()
		}
		if *no1344 {
			PKEFrodo1344()
		}
	}

	if *kem {
		if *no640 {
			go KEMFrodo640()
		}
		if *no976 {
			KEMFrodo976()
		}
		if *no1344 {
			KEMFrodo1344()
		}
	}
}

func PKEFrodo640() {
	frodo := frodo.Frodo640()
	pk, sk := frodo.KeyGen()
	m := []byte{0x34, 0x23, 0x1c, 0xca, 0xae, 0xde, 0xd4, 0xf8,
		0x85, 0x5a, 0x7f, 0x14, 0xc6, 0x17, 0x36, 0x35}
	ct := frodo.Enc(m, pk)
	frodo.Dec(ct, sk)
}
func PKEFrodo976() {
	frodo := frodo.Frodo976()
	pk, sk := frodo.KeyGen()
	m := []byte{0x62, 0x78, 0x42, 0x97, 0x2d, 0x3d, 0x4, 0x28,
		0xad, 0xcd, 0xea, 0x79, 0x71, 0x44, 0xb8, 0x9c,
		0x12, 0xe9, 0x95, 0xaf, 0x75, 0x72, 0x4c, 0xc7}
	ct := frodo.Enc(m, pk)
	frodo.Dec(ct, sk)
}

func PKEFrodo1344() {
	frodo := frodo.Frodo1344()
	pk, sk := frodo.KeyGen()
	m := []byte{0xea, 0x53, 0x99, 0xdd, 0x97, 0xd9, 0x64, 0xb3,
		0xa2, 0x8c, 0xa6, 0xa2, 0x68, 0x61, 0x82, 0x60,
		0x20, 0x63, 0x97, 0xc7, 0x3a, 0xae, 0x59, 0xbe,
		0x2a, 0x62, 0x7f, 0xa1, 0xfc, 0x8a, 0x39, 0x46}
	ct := frodo.Enc(m, pk)
	frodo.Dec(ct, sk)
}

func KEMFrodo640() {
	frodo := frodo.Frodo640()
	pk, sk := frodo.EncapsKeyGen()
	ct, _ := frodo.Encaps(pk)
	frodo.Decaps(ct, sk)
}

func KEMFrodo976() {
	frodo := frodo.Frodo976()
	pk, sk := frodo.EncapsKeyGen()
	ct, _ := frodo.Encaps(pk)
	frodo.Decaps(ct, sk)
}

func KEMFrodo1344() {
	frodo := frodo.Frodo1344()
	pk, sk := frodo.EncapsKeyGen()
	ct, _ := frodo.Encaps(pk)
	frodo.Decaps(ct, sk)
}
