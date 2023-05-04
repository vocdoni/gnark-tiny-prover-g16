package bits

import (
	"errors"
	"math/big"

	solver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"
)

// NNAF returns the NAF decomposition of the input. The number of digits is
// defined by the number of elements in the results slice.
var NNAF = nNaf

func init() {
	solver.RegisterHint(solver.NewHint("nnaf", NNAF))
}

func nNaf(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	return nafDecomposition(n, results)
}

// nafDecomposition gets the naf decomposition of a big number
func nafDecomposition(a *big.Int, results []*big.Int) error {
	if a == nil || a.Sign() == -1 {
		return errors.New("invalid input to naf decomposition; negative (or nil) big.Int not supported")
	}

	var zero, one, three big.Int

	one.SetUint64(1)
	three.SetUint64(3)

	n := 0

	// some buffers
	var buf, aCopy big.Int
	aCopy.Set(a)

	for aCopy.Cmp(&zero) != 0 && n < len(results) {

		// if aCopy % 2 == 0
		buf.And(&aCopy, &one)

		// aCopy even
		if buf.Cmp(&zero) == 0 {
			results[n].SetUint64(0)
		} else { // aCopy odd
			buf.And(&aCopy, &three)
			if buf.IsUint64() && buf.Uint64() == 3 {
				results[n].SetInt64(-1)
				aCopy.Add(&aCopy, &one)
			} else {
				results[n].SetUint64(1)
			}
		}
		aCopy.Rsh(&aCopy, 1)
		n++
	}
	for ; n < len(results); n++ {
		results[n].SetUint64(0)
	}

	return nil
}
