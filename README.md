# FrodoKEM

*Practical quantum-secure key encapsulation from generic lattices, golang realisation*

**Abstract.** The FrodoKEM schemes are designed to be _conservative_ yet practical post-quantum constructions whose security derives from cautious parameterizations of the well-studied learning with errors problem, which in turn has close connections to conjectured-hard problems on generic, “algebraically unstructured” [lattices](https://en.wikipedia.org/wiki/Lattice_(order)).

[https://frodokem.org/](https://frodokem.org/)

![](https://github.com/mariiatuzovska/frodokem/blob/master/img/frodo.jpg)

### Progress

- [x] Success mencode and decode matrices in Zq;
- [ ] Pack & Unpack matrices;
- [ ] Read all;

### List of packages and implementations

* FrodoKEM specification [`papers`](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf)
* Little-endian 16-bit-base strings [`util/bitstr`](https://github.com/mariiatuzovska/frodokem/util/bitstr/bitstr.go)
* Matrix encoding of bit strings [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go)
* Selected parameter sets [`frodo`](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go)

### How to run

0. [install GO](https://golang.org/doc/install?download=go1.13.darwin-amd64.pkg) if you need and initialise GOPATH

1. open terminal and go to your GOPATH folder

```
            $ cd ~/go/src
```

2. get this project

```
            $ go get "github.com/mariiatuzovska/frodokem"
```

3. create frodo.go in your GOPATH package

```
            $ touch frodo.go
```

4. follow this code

```
            package main

            import (
                "fmt"

                "github.com/mariiatuzovska/frodokem/frodo"
            )

            func main() {

                frodo640 := frodo.Frodo640()
                fmt.Println(frodo640)

            }    
```

5. run the program

```
            $ go run frodo.go
```
