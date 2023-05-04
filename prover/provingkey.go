package prover

import (
	"io"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
)

// ProvingKey is used by a Groth16 prover to encode a proof of a statement
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type ProvingKey struct {
	// domain
	Domain fft.Domain

	// [α]1, [β]1, [δ]1
	// [A(t)]1, [B(t)]1, [Kpk(t)]1, [Z(t)]1
	G1 struct {
		Alpha, Beta, Delta curve.G1Affine
		A, B, Z            []curve.G1Affine
		K                  []curve.G1Affine // the indexes correspond to the private wires
	}

	// [β]2, [δ]2, [B(t)]2
	G2 struct {
		Beta, Delta curve.G2Affine
		B           []curve.G2Affine
	}

	// if InfinityA[i] == true, the point G1.A[i] == infinity
	InfinityA, InfinityB     []bool
	NbInfinityA, NbInfinityB uint64

	CommitmentKey pedersen.ProvingKey
}

// ReadFrom attempts to decode a ProvingKey from reader
// ProvingKey must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed)
// note that we don't check that the points are on the curve or in the correct subgroup at this point
func (pk *ProvingKey) ReadFrom(r io.Reader) (int64, error) {
	return pk.readFrom(r)
}

// UnsafeReadFrom behaves like ReadFrom excepts it doesn't check if the decoded points are on the curve
// or in the correct subgroup
func (pk *ProvingKey) UnsafeReadFrom(r io.Reader) (int64, error) {
	return pk.readFrom(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) readFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	n, err := pk.Domain.ReadFrom(r)
	if err != nil {
		return n, err
	}

	dec := curve.NewDecoder(r, decOptions...)

	var nbWires uint64

	toDecode := []interface{}{
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		&pk.G1.A,
		&pk.G1.B,
		&pk.G1.Z,
		&pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		&pk.G2.B,
		&nbWires,
		&pk.NbInfinityA,
		&pk.NbInfinityB,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return n + dec.BytesRead(), err
		}
	}
	pk.InfinityA = make([]bool, nbWires)
	pk.InfinityB = make([]bool, nbWires)

	if err := dec.Decode(&pk.InfinityA); err != nil {
		return n + dec.BytesRead(), err
	}
	if err := dec.Decode(&pk.InfinityB); err != nil {
		return n + dec.BytesRead(), err
	}

	return n + dec.BytesRead(), nil
}
