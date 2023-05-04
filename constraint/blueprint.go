package cs

import csolver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"

type BlueprintID uint32

// Blueprint enable representing heterogenous constraints or instructions in a constraint system
// in a memory efficient way. Blueprints essentially help the frontend/ to "compress"
// constraints or instructions, and specify for the solving (or zksnark setup) part how to
// "decompress" and optionally "solve" the associated wires.
type Blueprint interface {
	// NbInputs return the number of calldata input this blueprint expects.
	// If this is unknown at compile time, implementation must return -1 and store
	// the actual number of inputs in the first index of the calldata.
	NbInputs() int

	// NbConstraints return the number of constraints this blueprint creates.
	NbConstraints() int
}

// Solver represents the state of a constraint system solver at runtime. Blueprint can interact
// with this object to perform run time logic, solve constraints and assign values in the solution.
type Solver interface {
	Field
	GetValue(cID, vID uint32) Element
	GetCoeff(cID uint32) Element
	SetValue(vID uint32, f Element)
	IsSolved(vID uint32) bool
}

// BlueprintSolvable represents a blueprint that knows how to solve itself.
type BlueprintSolvable interface {
	// Solve may return an error if the decoded constraint / calldata is unsolvable.
	Solve(s Solver, calldata []uint32) error
}

// BlueprintR1C indicates that the blueprint and associated calldata encodes a R1C
type BlueprintR1C interface {
	CompressR1C(c *R1C) []uint32
	DecompressR1C(into *R1C, calldata []uint32)
}

// BlueprintHint indicates that the blueprint and associated calldata encodes a hint.
type BlueprintHint interface {
	CompressHint(HintMapping) []uint32
	DecompressHint(h *HintMapping, calldata []uint32)
}

type BlueprintGenericHint struct{}

func (b *BlueprintGenericHint) DecompressHint(h *HintMapping, calldata []uint32) {
	// ignore first call data == nbInputs
	h.HintID = csolver.HintID(calldata[1])
	lenInputs := int(calldata[2])
	if cap(h.Inputs) >= lenInputs {
		h.Inputs = h.Inputs[:lenInputs]
	} else {
		h.Inputs = make([]LinearExpression, lenInputs)
	}

	j := 3
	for i := 0; i < lenInputs; i++ {
		n := int(calldata[j]) // len of linear expr
		j++
		if cap(h.Inputs[i]) >= n {
			h.Inputs[i] = h.Inputs[i][:0]
		} else {
			h.Inputs[i] = make(LinearExpression, 0, n)
		}
		for k := 0; k < n; k++ {
			h.Inputs[i] = append(h.Inputs[i], Term{CID: calldata[j], VID: calldata[j+1]})
			j += 2
		}
	}
	h.OutputRange.Start = calldata[j]
	h.OutputRange.End = calldata[j+1]
}

func (b *BlueprintGenericHint) CompressHint(h HintMapping) []uint32 {
	nbInputs := 1 // storing nb inputs
	nbInputs++    // hintID
	nbInputs++    // len(h.Inputs)
	for i := 0; i < len(h.Inputs); i++ {
		nbInputs++ // len of h.Inputs[i]
		nbInputs += len(h.Inputs[i]) * 2
	}

	nbInputs += 2 // output range start / end

	r := getBuffer(nbInputs)
	r = append(r, uint32(nbInputs))
	r = append(r, uint32(h.HintID))
	r = append(r, uint32(len(h.Inputs)))

	for _, l := range h.Inputs {
		r = append(r, uint32(len(l)))
		for _, t := range l {
			r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
		}
	}

	r = append(r, h.OutputRange.Start)
	r = append(r, h.OutputRange.End)
	if len(r) != nbInputs {
		panic("invalid")
	}
	return r
}

func (b *BlueprintGenericHint) NbInputs() int {
	return -1
}
func (b *BlueprintGenericHint) NbConstraints() int {
	return 0
}

// BlueprintGenericR1C implements Blueprint and BlueprintR1C.
// Encodes
//
//	L * R == 0
type BlueprintGenericR1C struct{}

func (b *BlueprintGenericR1C) NbInputs() int {
	// size of linear expressions are unknown.
	return -1
}
func (b *BlueprintGenericR1C) NbConstraints() int {
	return 1
}

func (b *BlueprintGenericR1C) CompressR1C(c *R1C) []uint32 {
	// we store total nb inputs, len L, len R, len O, and then the "flatten" linear expressions
	nbInputs := 4 + 2*(len(c.L)+len(c.R)+len(c.O))
	r := getBuffer(nbInputs)
	r = append(r, uint32(nbInputs))
	r = append(r, uint32(len(c.L)), uint32(len(c.R)), uint32(len(c.O)))
	for _, t := range c.L {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.R {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.O {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	return r
}

func (b *BlueprintGenericR1C) DecompressR1C(c *R1C, calldata []uint32) {
	copySlice := func(slice *LinearExpression, expectedLen, idx int) {
		if cap(*slice) >= expectedLen {
			(*slice) = (*slice)[:expectedLen]
		} else {
			(*slice) = make(LinearExpression, expectedLen, expectedLen*2)
		}
		for k := 0; k < expectedLen; k++ {
			(*slice)[k].CID = calldata[idx]
			idx++
			(*slice)[k].VID = calldata[idx]
			idx++
		}
	}

	lenL := int(calldata[1])
	lenR := int(calldata[2])
	lenO := int(calldata[3])

	const offset = 4
	copySlice(&c.L, lenL, offset)
	copySlice(&c.R, lenR, offset+2*lenL)
	copySlice(&c.O, lenO, offset+2*(lenL+lenR))
}

// since frontend is single threaded, to avoid allocating slices at each compress call
// we transit the compressed output through here
var bufCalldata []uint32

// getBuffer return a slice with at least the given capacity to use in Compress methods
// this is obviously not thread safe, but the frontend is single threaded anyway.
func getBuffer(size int) []uint32 {
	if cap(bufCalldata) < size {
		bufCalldata = make([]uint32, 0, size*2)
	}
	bufCalldata = bufCalldata[:0]
	return bufCalldata
}
