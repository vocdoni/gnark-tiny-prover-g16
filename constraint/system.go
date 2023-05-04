// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cs

import (
	"encoding/gob"
	csolver "github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"
	"github.com/vocdoni/gnark-tiny-prover-g16/witness"
	"io"
	"time"

	"github.com/consensys/gnark/logger"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const ConstrainSystemTypeR1CS = 1

type R1CS = system

// system is a curved-typed constraint.System with a concrete coefficient table (fr.Element)
type system struct {
	System
	CoeffTable
	field
}

func NewR1CS(capacity int) *R1CS {
	return newSystem(capacity, ConstrainSystemTypeR1CS)
}

func newSystem(capacity int, t int) *system {
	return &system{
		System:     NewSystem(fr.Modulus(), capacity, t),
		CoeffTable: newCoeffTable(capacity / 10),
	}
}

// Solve solves the constraint system with provided witness.
// If it's a R1CS returns R1CSSolution
// If it's a SparseR1CS returns SparseR1CSSolution
func (cs *system) Solve(witness witness.Witness, opts ...csolver.Option) (any, error) {
	log := logger.Logger().With().Int("nbConstraints", cs.GetNbConstraints()).Logger()
	start := time.Now()

	v := witness.Vector().(fr.Vector)

	// init the solver
	solver, err := newSolver(cs, v, opts...)
	if err != nil {
		log.Err(err).Send()
		return nil, err
	}

	// run it.
	if err := solver.run(); err != nil {
		log.Err(err).Send()
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("constraint system solver done")

	// format the solution
	// TODO @gbotrel revisit post-refactor
	var res R1CSSolution
	res.W = solver.values
	res.A = solver.a
	res.B = solver.b
	res.C = solver.c
	return &res, nil
}

// IsSolved
// Deprecated: use _, err := Solve(...) instead
func (cs *system) IsSolved(witness witness.Witness, opts ...csolver.Option) error {
	_, err := cs.Solve(witness, opts...)
	return err
}

// GetR1Cs return the list of R1C
func (cs *system) GetR1Cs() []R1C {
	toReturn := make([]R1C, 0, cs.GetNbConstraints())

	for _, inst := range cs.Instructions {
		blueprint := cs.Blueprints[inst.BlueprintID]
		if bc, ok := blueprint.(BlueprintR1C); ok {
			var r1c R1C
			bc.DecompressR1C(&r1c, cs.GetCallData(inst))
			toReturn = append(toReturn, r1c)
		} else {
			panic("not implemented")
		}
	}
	return toReturn
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (cs *system) GetNbCoefficients() int {
	return len(cs.Coefficients)
}

// CurveID returns curve ID as defined in gnark-crypto
func (cs *system) CurveID() ecc.ID {
	return ecc.BN254
}

// WriteTo encodes R1CS into provided io.Writer using gob
func (cs *system) WriteTo(w io.Writer) (int64, error) {
	_w := WriterCounter{W: w} // wraps writer to count the bytes written

	// encode our object
	encoder := gob.NewEncoder(&_w)

	return _w.N, encoder.Encode(cs)
}

// ReadFrom attempts to decode R1CS from io.Reader using gob
func (cs *system) ReadFrom(r io.Reader) (int64, error) {
	_r := ReaderCounter{R: r} // wraps reader to count the bytes written
	decoder := gob.NewDecoder(&_r)

	// initialize coeff table
	cs.CoeffTable = newCoeffTable(0)

	if err := decoder.Decode(cs); err != nil {
		return _r.N, err
	}

	if err := cs.CheckSerializationHeader(); err != nil {
		return _r.N, err
	}

	return _r.N, nil
}

func (cs *system) GetCoefficient(i int) (r Element) {
	copy(r[:], cs.Coefficients[i][:])
	return
}

// R1CSSolution represent a valid assignment to all the variables in the constraint system.
// The vector W such that Aw o Bw - Cw = 0
type R1CSSolution struct {
	W       fr.Vector
	A, B, C fr.Vector
}

func (t *R1CSSolution) WriteTo(w io.Writer) (int64, error) {
	n, err := t.W.WriteTo(w)
	if err != nil {
		return n, err
	}
	a, err := t.A.WriteTo(w)
	n += a
	if err != nil {
		return n, err
	}
	a, err = t.B.WriteTo(w)
	n += a
	if err != nil {
		return n, err
	}
	a, err = t.C.WriteTo(w)
	n += a
	return n, err
}

func (t *R1CSSolution) ReadFrom(r io.Reader) (int64, error) {
	n, err := t.W.ReadFrom(r)
	if err != nil {
		return n, err
	}
	a, err := t.A.ReadFrom(r)
	a += n
	if err != nil {
		return n, err
	}
	a, err = t.B.ReadFrom(r)
	a += n
	if err != nil {
		return n, err
	}
	a, err = t.C.ReadFrom(r)
	n += a
	return n, err
}
