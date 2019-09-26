# FrodoKEM

*Practical quantum-secure key encapsulation from generic lattices*

**Abstract.** The FrodoKEM schemes are designed to be _conservative_ yet practical post-quantum constructions whose security derives from cautious parameterizations of the well-studied learning with errors problem, which in turn has close connections to conjectured-hard problems on generic, “algebraically unstructured” [lattices](https://en.wikipedia.org/wiki/Lattice_(order)).

[https://frodokem.org/](https://frodokem.org/)

### List of packages and implementations

* FrodoKEM specification `[papers](https://github.com/mariiatuzovska/frodokem/blob/master/papers/FrodoKEM-specification-20190702.pdf)`
* Matrix encoding of bit strings `[frodo](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go)`
* Selected parameter sets `[frodo](https://github.com/mariiatuzovska/frodokem/blob/master/frodo/frodo.go)`

### How to run

0. [install GO](https://golang.org/doc/install?download=go1.13.darwin-amd64.pkg) if you need and initialise GOPATH

1. open terminal and go to your GOPATH folder

```
                $ cd ~/go/src
```

2. get this project

```
                $ go get "github.com/mariiatuzovska/cryptanalysis"
```

3. copy main.go to your GOPATH package

```
                $ cp ~/go/src/github.com/mariiatuzovska/frodokem/main.go ~/go/src
```

4. run the program

```
                $ go run lab1.go
```

... wait. i am hard working on it. gophers are hard working on it.

### True story, bro

```
        func Frodo640() *Parameters {

	        param := new(Parameters)

	        param.no = 640
    	    param.q = 32768
	        param.D = 15
	        param.B = 2
    	    param.m = 8
	        param.n = 8
	        param.lseedA = 128
    	    param.lseedSE = 128
	        param.l = 128

	        return param
        }
```