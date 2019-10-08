# FrodoKEM

*Practical quantum-secure key encapsulation from generic lattices.*

**Abstract.** The FrodoKEM schemes are designed to be _conservative_ yet practical post-quantum constructions whose security derives from cautious parameterizations of the well-studied [learning with errors problem](https://en.wikipedia.org/wiki/Learning_with_errors), which in turn has close connections to conjectured-hard problems on generic, “algebraically unstructured” [lattices](https://en.wikipedia.org/wiki/Lattice_(order)).

[https://frodokem.org/](https://frodokem.org/)

![](https://github.com/mariiatuzovska/frodokem/blob/master/img/frodo.jpg)

## Progress 40%

- [x] Selected parameter sets;
- [x] Success encode & decode matrices in Zq;
- [x] Success pack & unpack matrices;
- [ ] Read all in specification;
- [x] Sampling from the error distribution;
- [x] Pseudorandom matrix generation using SHAKE128, SHAKE256;
- [ ] IND-CPA-secure public-key encryption (PKE) scheme (encryption/decryption, key generation);
- [ ] IND-CCA-secure key encapsulation mechanism (KEM);

- [ ] Writing tests;
- [ ] Optimising computational process.

## Math & Implementations

**Vectors and matrices over the ring.** The ring of integers Z for a positive integer q, the quotient ring of integers modulo q is denoted by Zq = Z/qZ.

**Realisation of matrices over the ring.** Matrix A (m*n) contains unsigned 16-bit numbers in ring of integers modulo q.

**Realisation of bit-strings.** Bit string *s* with length *len* realised like []byte slice with length *(len / 8)* in little-endian order.

**Learning With Errors.** The security of PKE and KEM relies on the hardness of the Learning With Errors (LWE) problem. 

**LWE distribution.** Let n,q be positive integers, and let X be a distribution over Z. For an *s* in (Zq)^n, the LWE *distribution* A(s,x) is the distribution over (Zq)^n \* Zq obtained by choosing *a* in (Zq)^n uniformly at random and an integer error *e* in Z from X, and outputting the pair <*a*, <*a*, *s*> + *e* (mod q)> in (Zq)^n \* Zq.

**Pseudorandom matrix generation.** As NIST currently does not standardize such a primitive, so I choose proposals in [`FrodoKEM specification`](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf) to use SHAKE128 & SHAKE256.

## List of implementations/packages

:point_right: FrodoKEM specification [`papers`](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf);

:point_right: Matrix encoding of bit strings (decoding) [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go);

:point_right: Deterministic random bit generation & pseudorandom matrix generation using SHAKE128 [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go);

:point_right: SHAKE128 [`golang.org/x/crypto/sha3`](https://godoc.org/golang.org/x/crypto/sha3);

:point_right: Selected parameter sets [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go);

:point_right: Sampling from the error distribution [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go);

:point_right: IND-CPA-secure public-key encryption scheme [`pke`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/pke.go);

:point_right: IND-CCA-secure key encapsulation mechanism [`kem`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/kem.go);

## Advantages & Disadvantages of my implementation

:ok_hand: You can add your custom parameters following code in function [`func Frodo640`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go) (if you understand [main theory](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf)) and use them in any future work with FrodoKEM;

:poop: It is hard mathematical task to get the parameters;

:heart_eyes_cat: Pretty native Golang: using best practices of language,

:space_invader: Written tests (soon).

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
            $ go get "github.com/mariiatuzovska/frodokem"
            $ go get "golang.org/x/crypto"
```

## Example

### Encryption & Decryption 

```
    package main

    import (
        "fmt"
        
        "github.com/mariiatuzovska/frodokem/frodo"
    )

    func main() {

        frodo640 := frodo.Frodo640()
        pk, sk := frodo976.KeyGen()

        m := []byte("This is my pure frodo976")
        
	    ct := frodo.Enc(m, pk)
	    pt := frodo.Dec(ct, sk)

	    fmt.Printf(string(pt))
        
    } 

```

![](https://github.com/mariiatuzovska/frodokem/blob/master/img/kem.jpg)
