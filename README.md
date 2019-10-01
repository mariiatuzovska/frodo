# FrodoKEM

*Practical quantum-secure key encapsulation from generic lattices.*

**Abstract.** The FrodoKEM schemes are designed to be _conservative_ yet practical post-quantum constructions whose security derives from cautious parameterizations of the well-studied [learning with errors problem](https://en.wikipedia.org/wiki/Learning_with_errors), which in turn has close connections to conjectured-hard problems on generic, “algebraically unstructured” [lattices](https://en.wikipedia.org/wiki/Lattice_(order)).

[https://frodokem.org/](https://frodokem.org/)

![](https://github.com/mariiatuzovska/frodokem/blob/master/img/frodo.jpg)

## Progress

- [x] Selected parameter sets;
- [x] Success encode & decode matrices in Zq;
- [x] Success pack & unpack matrices;
- [ ] Read all in specification;
- [x] Sampling from the error distribution;
- [x] Pseudorandom matrix generation using SHAKE128, SHAKE256;
- [ ] IND-CPA-secure public-key encryption (PKE) scheme (encryption/decryption, key generation);
- [ ] Transform from IND-CPA PKE to IND-CCA key encapsulation mechanism (KEM);
- [ ] IND-CCA-secure key encapsulation mechanism (KEM).

## Math

### Vectors and matrices over the ring

The ring of integers Z for a positive integer q, the quotient ring of integers modulo q is denoted by Zq = Z/qZ.

### Learning With Errors

The security of PKE and KEM relies on the hardness of the Learning With Errors (LWE) problem. 

**LWE distribution.** Let n,q be positive integers, and let X be a distribution over Z. For an *s* in (Zq)^n, the LWE *distribution* A(s,x) is the distribution over (Zq)^n \* Zq obtained by choosing *a* in (Zq)^n uniformly at random and an integer error *e* in Z from X, and outputting the pair <*a*, <*a*, *s*> + *e* (mod q)> in (Zq)^n \* Zq.

### Pseudorandom matrix generation

As NIST currently does not standardize such a primitive, so I choose proposals in [`FrodoKEM specification`](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf) to use SHAKE128 & SHAKE256.

## List of implementations/packages

:point_right: FrodoKEM specification [`papers`](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf);

:point_right: Little-endian 16-bit-base strings [`util/bitstr`](https://github.com/mariiatuzovska/frodokem/blob/master/util/bitstr/bitstr.go);

:point_right: Matrix encoding of bit strings [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go);

:point_right: Selected parameter sets [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go);

:point_right: Deterministic random bit generation using SHAKE128 [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go);

:point_right: SHAKE128 [`golang.org/x/crypto/sha3`](https://godoc.org/golang.org/x/crypto/sha3);

:point_right: Generation of key pairs [`pke`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/pke.go);

## Advantages & Disadvantages of my implementation

:ok_hand: You can add your custom parameters following code in function [`func Frodo640`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go) (if you understand [main theory](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf)) and use them in any future work with FrodoKEM;

:poop: It is hard mathematical task to get the parameters;

:poop: Not good implementation of bit-sequences, maybe will be better in time;

:heart_eyes_cat: Pretty native Golang.

## Inspiration

:green_heart: [microsoft git](https://github.com/Microsoft/PQCrypto-LWEKE)

:purple_heart: [microsoft research](https://www.microsoft.com/en-us/research/?from=http%3A%2F%2Fresearch.microsoft.com%2F)

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

3. create frodo.go in your GOPATH package

```
            $ touch frodo.go
```

4. follow this code to check current work of library

```
    package main

    import (
        "fmt"
        
        "github.com/mariiatuzovska/frodokem/frodo"
    )

    func main() {

        frodo640 := frodo.Frodo640()
        pk, sk := frodo640.KeyGen()
        
    } 

```

5. run the program

```
            $ go run frodo.go
```

## Examples 
