# Frodo

*Practical quantum-secure key encapsulation from generic lattices library.*

**Abstract.** The FrodoKEM schemes are designed to be _conservative_ yet practical post-quantum constructions whose security derives from cautious parameterizations of the well-studied [learning with errors problem](https://en.wikipedia.org/wiki/Learning_with_errors), which in turn has close connections to conjectured-hard problems on generic, “algebraically unstructured” [lattices](https://en.wikipedia.org/wiki/Lattice_(order)).

[https://frodokem.org/](https://frodokem.org/)

![](https://github.com/mariiatuzovska/frodo/blob/master/img/frodo.jpg)

## Progress 

- [x] Selected parameter sets;
- [x] Success encode & decode matrices in Zq;
- [x] Success pack & unpack matrices;
- [x] Sampling from the error distribution;
- [x] Pseudorandom matrix generation using SHAKE128, SHAKE256;
- [x] IND-CPA-secure public-key encryption (PKE) scheme (encryption/decryption, key generation);
- [x] IND-CCA-secure key encapsulation mechanism (KEM);

- [x] Written tests.

## Math & Implementations

The FrodoPKE scheme from this submission is an instantiation and implementation of the Lindner scheme with some modifications, such as the pseudorandom generation of the public matrix A from a small seed, more balanced key and ciphertext sizes, and new LWE parameters [\[FKEM\]](https://github.com/mariiatuzovska/frodo/blob/master/papers/FrodoKEM-specification-20190702.pdf).
The security of every public-key cryptosystem depends on the presumed intractability of one or more computational problems. In lattice-based cryptography, the (plain) LWE problem relates to solving a "noisy" linear system modulo a known integer; it can also be interpreted as the problem of decoding a random "unstructured" lattice from a certain class.


**Vectors and matrices over the ring.** The ring of integers Z for a positive integer q, the quotient ring of integers modulo q is denoted by Zq = Z/qZ.

**Realisation of matrices over the ring.** Matrix A (m*n) contains unsigned 16-bit numbers in ring of integers modulo q.

**Realisation of bit-strings.** Bit string *s* with length *len* defined like []byte slice with length *(len / 8)* in little-endian order.

**Learning With Errors.** The security of PKE and KEM relies on the hardness of the Learning With Errors (LWE) problem. Input instances are chosen at random from a prescribed probability distribution. Some parameterizations of LWE admit (quantum or classical) reductions from worst-case lattice problems. That is, any algorithm that solves n-dimensional LWE (with some non-negligible advantage) can be converted with some polynomial overhead into a (quantum) algorithm that solves certain short-vector problems on any n-dimensional lattice (with high probability). Therefore, if the latter problems have some (quantumly) hard instances, then random instances of LWE are also hard [\[FKEM\]](https://github.com/mariiatuzovska/frodo/blob/master/papers/FrodoKEM-specification-20190702.pdf).

**LWE distribution.** Let n,q be positive integers, and let X be a distribution over Z. For an *s* in (Zq)^n, the LWE *distribution* A(s,x) is the distribution over (Zq)^n \* Zq obtained by choosing *a* in (Zq)^n uniformly at random and an integer error *e* in Z from X, and outputting the pair <*a*, <*a*, *s*> + *e* (mod q)> in (Zq)^n \* Zq.

**Pseudorandom matrix generation.** As NIST currently does not standardize such a primitive, so I choose proposals in [\[FKEM\]](https://github.com/mariiatuzovska/frodo/blob/master/papers/FrodoKEM-specification-20190702.pdf) to use SHAKE128 & SHAKE256.

## List of implementations/packages

:point_right: FrodoKEM specification [`papers`](https://github.com/mariiatuzovska/frodo/blob/master/papers/FrodoKEM-specification-20190702.pdf);

:point_right: Matrix encoding of bit strings (decoding) [`frodo`](https://github.com/mariiatuzovska/frodo/blob/master/frodo/frodo.go);

:point_right: Deterministic random bit generation & pseudorandom matrix generation using SHAKE128 [`frodo`](https://github.com/mariiatuzovska/frodo/blob/master/frodo.go);

:point_right: SHAKE128 [`golang.org/x/crypto/sha3`](https://godoc.org/golang.org/x/crypto/sha3);

:point_right: Selected parameter sets [`frodo`](https://github.com/mariiatuzovska/frodo/blob/master/frodo.go);

:point_right: Sampling from the error distribution [`frodo`](https://github.com/mariiatuzovska/frodo/blob/master/frodo.go);

:point_right: IND-CPA-secure public-key encryption scheme [`pke`](https://github.com/mariiatuzovska/frodo/blob/master/pke.go);

:point_right: IND-CCA-secure key encapsulation mechanism [`kem`](https://github.com/mariiatuzovska/frodo/blob/master/kem.go);

:point_right: Testing PKE & KEM, unit tests [`test`](https://github.com/mariiatuzovska/frodo/blob/master/frodo_test.go);

## Advantages & Disadvantages of my implementation

:heart_eyes_cat: Pretty native Golang: using best practices of language;

:sleeping: slower than portable C;

:space_invader: written tests.

## Inspiration

:boom: [microsoft git](https://github.com/Microsoft/PQCrypto-LWEKE)

:boom: [microsoft research](https://www.microsoft.com/en-us/research/?from=http%3A%2F%2Fresearch.microsoft.com%2F)

## How to run

0. [install GO](https://golang.org/doc/install?download=go1.13.darwin-amd64.pkg) if you need and initialise GOPATH

1. open terminal and go to your GOPATH folder

```
            $ cd ~/go/src
```

2. get this project and [golang.org/x/crypto](https://godoc.org/golang.org/x/crypto) library

```
            $ go get "github.com/mariiatuzovska/frodo"
            $ go get "golang.org/x/crypto"
```

3. run test

```
	    $ go test 'github.com/mariiatuzovska/frodo'
```

4. if test ok, use anywhere :smiling_imp:

## Example

### Encryption & Decryption 

```
    package main

    import (
        "fmt"
        
        "github.com/mariiatuzovska/frodo"
    )

    func main() {

        frodo := frodo.Frodo976()
        pk, sk := frodo.KeyGen()

        m := []byte("This is my pure frodo976")
        
	ct := frodo.Enc(m, pk)
	pt := frodo.Dec(ct, sk)

	fmt.Println(string(pt))
        
    } 

```

### Encaps & Decaps

```
    package main

    import (
        "fmt"
        
        "github.com/mariiatuzovska/frodo"
    )

    func main() {

        frodo := frodo.Frodo1344()

	pk, sk := frodo.EncapsKeyGen()
	ct, ss := frodo.Encaps(pk)
	s2 := frodo.Decaps(ct, sk)

	fmt.Printf("%x\n", ss)
        fmt.Printf("%x\n", s2)
    } 

```

![](https://github.com/mariiatuzovska/frodo/blob/master/img/kem.jpg)
