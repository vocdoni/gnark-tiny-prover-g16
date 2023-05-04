package bits

import (
	"math/big"

	solver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"
)

// NTrits returns the first trits of the input. The number of returned trits is
// defined by the length of the results slice.
var NTrits = nTrits

func init() {
	solver.RegisterHint(solver.NewHint("n_trits", NTrits))
}

func nTrits(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	n := inputs[0]
	// TODO using big.Int Text method is likely not cheap
	base3 := n.Text(3)
	i := 0
	for j := len(base3) - 1; j >= 0 && i < len(results); j-- {
		results[i].SetUint64(uint64(base3[j] - 48))
		i++
	}
	for ; i < len(results); i++ {
		results[i].SetUint64(0)
	}

	return nil
}
