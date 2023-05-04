package bits

import (
	"errors"
)

// Base defines the base for decomposing the scalar into digits.
type Base uint8

const (
	// Binary base decomposes scalar into bits (0-1)
	Binary Base = 2

	// Ternary base decomposes scalar into trits (0-1-2)
	Ternary Base = 3
)

type baseConversionConfig struct {
	NbDigits             int
	UnconstrainedOutputs bool
	UnconstrainedInputs  bool
}

// BaseConversionOption configures the behaviour of scalar decomposition.
type BaseConversionOption func(opt *baseConversionConfig) error

// WithNbDigits sets the resulting number of digits (nbDigits) to be used in the base conversion.
// nbDigits must be > 0. If nbDigits is lower than the length of full decomposition and
// WithUnconstrainedOutputs option is not used, then this function generates an unsatisfiable
// constraint. If WithNbDigits option is not set, then the full decomposition is returned.
func WithNbDigits(nbDigits int) BaseConversionOption {
	return func(opt *baseConversionConfig) error {
		if nbDigits <= 0 {
			return errors.New("nbDigits <= 0")
		}
		opt.NbDigits = nbDigits
		return nil
	}
}

// WithUnconstrainedOutputs sets the bit conversion API to NOT constrain the output bits.
// This is UNSAFE but is useful when the outputs are already constrained by other circuit
// constraints.
// The sum of the digits will is constrained like so Σbi = Σ (base**i * digits[i])
// But the individual digits are not constrained to be valid digits in base b.
func WithUnconstrainedOutputs() BaseConversionOption {
	return func(opt *baseConversionConfig) error {
		opt.UnconstrainedOutputs = true
		return nil
	}
}

// WithUnconstrainedInputs indicates to the FromBase apis to constrain its inputs (digits) to
// ensure they are valid digits in base b. For example, FromBinary without this option will add
// 1 constraint per bit to ensure it is either 0 or 1.
func WithUnconstrainedInputs() BaseConversionOption {
	return func(opt *baseConversionConfig) error {
		opt.UnconstrainedInputs = true
		return nil
	}
}
