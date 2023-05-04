package hintsolver

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/logger"
)

func init() {
	RegisterHint(Hint{Fn: InvZeroHint, ID: GetHintID("inv_zero")})
}

var (
	registry  = make(map[HintID]HintFn)
	registryM sync.RWMutex
)

// RegisterHint registers a hint function in the global registry.
func RegisterHint(hints ...Hint) {
	registryM.Lock()
	defer registryM.Unlock()
	for _, hint := range hints {
		if _, ok := registry[hint.ID]; ok {
			log := logger.Logger()
			log.Warn().Str("id", fmt.Sprintf("%d", hint.ID)).Msg("function registered multiple times")
			return
		}
		registry[hint.ID] = hint.Fn
	}
}

// GetRegisteredHints returns all registered hint functions.
func GetRegisteredHints() map[HintID]HintFn {
	registryM.RLock()
	defer registryM.RUnlock()
	hints := make(map[HintID]HintFn)
	for id, v := range registry {
		hints[id] = v
	}
	return hints
}

// InvZeroHint computes the value 1/a for the single input a. If a == 0, returns 0.
func InvZeroHint(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// save input
	result.Set(inputs[0])

	// a == 0, return
	if result.IsUint64() && result.Uint64() == 0 {
		return nil
	}

	result.ModInverse(result, q)
	return nil
}
