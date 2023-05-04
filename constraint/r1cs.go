package cs

import "strings"

// R1C used to compute the wires
type R1C struct {
	L, R, O LinearExpression
}

// WireIterator implements constraint.Iterable
func (r1c *R1C) WireIterator() func() int {
	curr := 0
	return func() int {
		if curr < len(r1c.L) {
			curr++
			return r1c.L[curr-1].WireID()
		}
		if curr < len(r1c.L)+len(r1c.R) {
			curr++
			return r1c.R[curr-1-len(r1c.L)].WireID()
		}
		if curr < len(r1c.L)+len(r1c.R)+len(r1c.O) {
			curr++
			return r1c.O[curr-1-len(r1c.L)-len(r1c.R)].WireID()
		}
		return -1
	}
}

// String formats a R1C as L⋅R == O
func (r1c *R1C) String(r Resolver) string {
	sbb := NewStringBuilder(r)
	sbb.WriteLinearExpression(r1c.L)
	sbb.WriteString(" ⋅ ")
	sbb.WriteLinearExpression(r1c.R)
	sbb.WriteString(" == ")
	sbb.WriteLinearExpression(r1c.O)
	return sbb.String()
}

// Resolver allows pretty printing of constraints.
type Resolver interface {
	CoeffToString(coeffID int) string
	VariableToString(variableID int) string
}

// StringBuilder is a helper to build string from constraints, linear expressions or terms.
// It embeds a strings.Builder object for convenience.
type StringBuilder struct {
	strings.Builder
	Resolver
}

// NewStringBuilder returns a new StringBuilder.
func NewStringBuilder(r Resolver) *StringBuilder {
	return &StringBuilder{Resolver: r}
}

// WriteLinearExpression appends the linear expression to the current buffer
func (sbb *StringBuilder) WriteLinearExpression(l LinearExpression) {
	for i := 0; i < len(l); i++ {
		sbb.WriteTerm(l[i])
		if i+1 < len(l) {
			sbb.WriteString(" + ")
		}
	}
}

// A LinearExpression is a linear combination of Term
type LinearExpression []Term

// Clone returns a copy of the underlying slice
func (l LinearExpression) Clone() LinearExpression {
	res := make(LinearExpression, len(l))
	copy(res, l)
	return res
}

func (l LinearExpression) String(r Resolver) string {
	sbb := NewStringBuilder(r)
	sbb.WriteLinearExpression(l)
	return sbb.String()
}

// WriteLinearExpression appends the term to the current buffer
func (sbb *StringBuilder) WriteTerm(t Term) {
	if t.CoeffID() == CoeffIdZero {
		sbb.WriteByte('0')
		return
	}
	vs := sbb.VariableToString(t.WireID())
	if t.CoeffID() == CoeffIdOne {
		// print the variable only
		sbb.WriteString(vs)
		return
	}
	sbb.WriteString(sbb.CoeffToString(t.CoeffID()))
	if t.WireID() == 0 && vs == "1" {
		// special path for R1CS; the one wire so let's just print the coeff for clarity
		return
	}
	sbb.WriteString("⋅")
	sbb.WriteString(vs)
}
