package cs

import "math"

// ids of the coefficients with simple values in any cs.coeffs slice.
const (
	CoeffIdZero = iota
	CoeffIdOne
	CoeffIdTwo
	CoeffIdMinusOne
	CoeffIdMinusTwo
)

// Term represents a coeff * variable in a constraint system
type Term struct {
	CID, VID uint32
}

func (t *Term) MarkConstant() {
	t.VID = math.MaxUint32
}

func (t *Term) IsConstant() bool {
	return t.VID == math.MaxUint32
}

func (t *Term) WireID() int {
	return int(t.VID)
}

func (t *Term) CoeffID() int {
	return int(t.CID)
}

func (t Term) String(r Resolver) string {
	sbb := NewStringBuilder(r)
	sbb.WriteTerm(t)
	return sbb.String()
}
