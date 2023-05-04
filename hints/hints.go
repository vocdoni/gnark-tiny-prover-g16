package hints

import (
	"sync"

	solver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"

	"github.com/vocdoni/gnark-tiny-prover-g16/hints/math/bits"
	"github.com/vocdoni/gnark-tiny-prover-g16/hints/math/emulated"
	"github.com/vocdoni/gnark-tiny-prover-g16/hints/rangecheck"
	"github.com/vocdoni/gnark-tiny-prover-g16/hints/selector"
)

var registerOnce sync.Once

// RegisterHints register all gnark/std hints
// In the case where the Solver/Prover code is loaded alongside the circuit, this is not useful.
// However, if a Solver/Prover services consumes serialized constraint systems, it has no way to
// know which hints were registered; caller code may add them through backend.WithHints(...).
func RegisterHints() {
	registerOnce.Do(registerHints)
}

func registerHints() {
	// note that importing these packages may already trigger a call to solver.RegisterHint(...)
	solver.RegisterHint(solver.NewHint("n_trits", bits.NTrits))
	solver.RegisterHint(solver.NewHint("nnaf", bits.NNAF))
	solver.RegisterHint(solver.NewHint("ith_bit", bits.IthBit))
	solver.RegisterHint(solver.NewHint("n_bits", bits.NBits))
	solver.RegisterHint(selector.GetHints()...)
	solver.RegisterHint(emulated.GetHints()...)
	solver.RegisterHint(solver.NewHint("count", rangecheck.CountHint))
	solver.RegisterHint(solver.NewHint("decompose", rangecheck.DecomposeHint))
}
