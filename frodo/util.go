package frodo

import "math/bits"

// A (n1*m1); B (n2*m2) => A * B = C (n1*m2)
func (param *Parameters) mulMatrices(A, B [][]uint16) [][]uint16 {

	C := make([][]uint16, len(A))
	for i := 0; i < len(A); i++ {
		C[i] = make([]uint16, len(B[0]))
		for j := 0; j < len(B[0]); j++ {
			for k := 0; k < len(A); k++ {
				mul, _ := bits.Mul32(uint32(A[i][k]), uint32(B[k][j]))
				C[i][j] = uint16(mul+uint32(C[i][j])) & param.q
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
			for k := 0; k < len(A); k++ {
				mul, _ := bits.Mul32(uint32(A[i][k]), uint32(B[k][j]))
				C[i][j] = uint16(mul+uint32(C[i][j])) & param.q
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
			add, _ := bits.Add32(uint32(A[i][j]), uint32(B[i][j]), 0)
			C[i][j] = uint16(add) & param.q
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
				diff, _ := bits.Sub32(uint32(A[i][j]), uint32(B[i][j]), 0)
				C[i][j] = uint16(diff) & param.q
			} else {
				diff, _ := bits.Sub32(uint32(B[i][j]), uint32(A[i][j]), 0)
				C[i][j] = (param.q - (uint16(diff) & param.q) + 1) & param.q
			}
		}
	}
	return C
}
