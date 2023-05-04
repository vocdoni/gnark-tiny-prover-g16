// Package selector provides a lookup table and map based on linear scan.
//
// The native [frontend.API] provides 1- and 2-bit lookups through the interface
// methods Select and Lookup2. This package extends the lookups to
// arbitrary-sized vectors. The lookups can be performed using the index of the
// elements (function [Mux]) or using a key, for which the user needs to provide
// the slice of keys (function [Map]).
//
// The implementation uses linear scan over all inputs, so the constraint count
// for every invocation of the function is C*len(values)+1, where:
//   - for R1CS, C = 3
//   - for PLONK, C = 5
package selector

import (
	"math/big"

	solver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"
)

func init() {
	// register hints
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in this package. This method is
// useful for registering all hints in the solver.
func GetHints() []solver.Hint {
	return []solver.Hint{
		solver.NewHint("step_output", stepOutput),
		solver.NewHint("mux_indicators", muxIndicators),
		solver.NewHint("map_indicators", mapIndicators)}
}

// muxIndicators is a hint function used within [Mux] function. It must be
// provided to the prover when circuit uses it.
func muxIndicators(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	sel := inputs[0]
	for i := 0; i < len(results); i++ {
		// i is an int which can be int32 or int64. We convert i to int64 then to bigInt, which is safe. We should
		// not convert sel to int64.
		if sel.Cmp(big.NewInt(int64(i))) == 0 {
			results[i].SetUint64(1)
		} else {
			results[i].SetUint64(0)
		}
	}
	return nil
}

// mapIndicators is a hint function used within [Map] function. It must be
// provided to the prover when circuit uses it.
func mapIndicators(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	key := inputs[len(inputs)-1]
	// We must make sure that we are initializing all elements of results
	for i := 0; i < len(results); i++ {
		if key.Cmp(inputs[i]) == 0 {
			results[i].SetUint64(1)
		} else {
			results[i].SetUint64(0)
		}
	}
	return nil
}
