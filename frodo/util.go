package frodo

import (
	"math"
)

func (param *Parameters) ec(k uint16) uint16 {
	t := uint16(1) << uint(param.D-param.B)
	return uint16(t*k) & param.q
}

func (param *Parameters) dc(c uint16) uint16 {
	b, d := uint16(1)<<uint(param.B), uint32(1)<<uint(param.D-param.B)
	r := float64(c) / float64(d)
	return uint16(math.Round(r)) & (b - 1)
}

// A (n1*m1); B (n2*m2) => A * B = C (n1*m2)
func (param *Parameters) mulMatrices(A, B [][]uint16) [][]uint16 {

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(B[0]))
		for j := 0; j < len(B[0]); j++ {
			for k := 0; k < len(A[0]); k++ {
				C[i][j] = uint16(uint64(A[i][k])*uint64(B[k][j])+uint64(C[i][j])) & param.q
			}
		}
	}
	return C
}

func (param *Parameters) mulAddMatrices(A, B, E [][]uint16) [][]uint16 {

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(B[0]))
		for j := 0; j < len(B[0]); j++ {
			C[i][j] = E[i][j]
			for k := 0; k < len(A[0]); k++ {
				C[i][j] = uint16(uint64(A[i][k])*uint64(B[k][j])+uint64(C[i][j])) & param.q
			}
		}
	}
	return C
}

func (param *Parameters) sumMatrices(A, B [][]uint16) [][]uint16 { // for symmetric matrices

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(A[0]))
		for j := 0; j < len(A[0]); j++ {
			C[i][j] = uint16(uint32(A[i][j])+uint32(B[i][j])) & param.q
		}
	}
	return C
}

func (param *Parameters) subMatrices(A, B [][]uint16) [][]uint16 { // for symmetric matrices

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(A[0]))
		for j := 0; j < len(A[0]); j++ {
			if A[i][j] >= B[i][j] {
				C[i][j] = (A[i][j] - B[i][j]) & param.q
			} else {
				C[i][j] = (param.q - B[i][j] + A[i][j] + 1) & param.q
			}
		}
	}
	return C
}
