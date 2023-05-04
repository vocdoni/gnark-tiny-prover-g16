package bits

import (
	"math/big"

	solver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"
)

func init() {
	// register hints
	solver.RegisterHint(solver.NewHint("ith_bit", IthBit))
	solver.RegisterHint(solver.NewHint("n_bits", NBits))
}

// IthBit returns the i-tb bit the input. The function expects exactly two
// integer inputs i and n, takes the little-endian bit representation of n and
// returns its i-th bit.
func IthBit(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	result := results[0]
	if !inputs[1].IsUint64() {
		result.SetUint64(0)
		return nil
	}

	result.SetUint64(uint64(inputs[0].Bit(int(inputs[1].Uint64()))))
	return nil
}

// NBits returns the first bits of the input. The number of returned bits is
// defined by the length of the results slice.
func NBits(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	for i := 0; i < len(results); i++ {
		results[i].SetUint64(uint64(n.Bit(i)))
	}
	return nil
}
