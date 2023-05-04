package rangecheck

import (
	"fmt"
	"math/big"

	solver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"
)

type ctxCheckerKey struct{}

func init() {
	solver.RegisterHint(solver.NewHint("decompose", DecomposeHint), solver.NewHint("count", CountHint))
}

func decompSize(varSize int, limbSize int) int {
	return (varSize + limbSize - 1) / limbSize
}

// DecomposeHint is a hint used for range checking with commitment. It
// decomposes large variables into chunks which can be individually range-check
// in the native range.
func DecomposeHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("input must be 3 elements")
	}
	if !inputs[0].IsUint64() || !inputs[1].IsUint64() {
		return fmt.Errorf("first two inputs have to be uint64")
	}
	varSize := int(inputs[0].Int64())
	limbSize := int(inputs[1].Int64())
	val := inputs[2]
	nbLimbs := decompSize(varSize, limbSize)
	if len(outputs) != nbLimbs {
		return fmt.Errorf("need %d outputs instead to decompose", nbLimbs)
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(limbSize))
	tmp := new(big.Int).Set(val)
	for i := 0; i < len(outputs); i++ {
		outputs[i].Mod(tmp, base)
		tmp.Rsh(tmp, uint(limbSize))
	}
	return nil
}

// CountHint is a hint function which is used in range checking using
// commitment. It counts the occurences of checked variables in the range and
// returns the counts.
func CountHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nbVals := len(outputs)
	if len(outputs) != nbVals {
		return fmt.Errorf("output size %d does not match range size %d", len(outputs), nbVals)
	}
	counts := make(map[uint64]uint64, nbVals)
	for i := 0; i < len(inputs); i++ {
		if !inputs[i].IsUint64() {
			return fmt.Errorf("input %d not uint64", i)
		}
		c := inputs[i].Uint64()
		counts[c]++
	}
	for i := 0; i < nbVals; i++ {
		outputs[i].SetUint64(counts[uint64(i)])
	}
	return nil
}
