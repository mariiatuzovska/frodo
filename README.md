# FrodoKEM

*Practical quantum-secure key encapsulation from generic lattices*

**Abstract.** The FrodoKEM schemes are designed to be _conservative_ yet practical post-quantum constructions whose security derives from cautious parameterizations of the well-studied learning with errors problem, which in turn has close connections to conjectured-hard problems on generic, “algebraically unstructured” [lattices](https://en.wikipedia.org/wiki/Lattice_(order)).

[https://frodokem.org/](https://frodokem.org/)

### List of packages and implementations

* FrodoKEM specification [`papers`](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf)
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

... wait. i am hard working on it. gophers are hard working on it.