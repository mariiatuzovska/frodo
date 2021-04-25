# Frodo performance test

*protobuf needed*

### CPU performance
* `go get github.com/google/pprof`
* `go run main.go -cpu -kem -640 -976 -1344`
* `go tool pprof -top  ./profile.pb.gz`

### Memory performance
* `go get github.com/google/pprof`
* `go run main.go -mem -kem -640 -976 -1344`
* `go tool pprof -top  ./profile.pb.gz`