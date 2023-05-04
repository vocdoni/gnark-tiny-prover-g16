package selector

import (
	"math/big"
)

// stepOutput is a hint function used within [StepMask] function. It must be
// provided to the prover when circuit uses it.
func stepOutput(_ *big.Int, inputs, results []*big.Int) error {
	stepPos := inputs[0]
	startValue := inputs[1]
	endValue := inputs[2]
	for i := 0; i < len(results); i++ {
		if i < int(stepPos.Int64()) {
			results[i].Set(startValue)
		} else {
			results[i].Set(endValue)
		}
	}
	return nil
}
