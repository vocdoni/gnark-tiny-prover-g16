package cs

import (
	"io"
	"math/big"
	"reflect"
)

type WriterCounter struct {
	W io.Writer
	N int64
}

func (w *WriterCounter) Write(p []byte) (n int, err error) {
	n, err = w.W.Write(p)
	w.N += int64(n)
	return
}

type ReaderCounter struct {
	R io.Reader
	N int64
}

func (cr *ReaderCounter) Read(p []byte) (int, error) {
	n, err := cr.R.Read(p)
	cr.N += int64(n)
	return n, err
}

type toBigIntInterface interface {
	ToBigIntRegular(res *big.Int) *big.Int
}

// FromInterface converts an interface to a big.Int element
//
// input must be primitive (uintXX, intXX, []byte, string) or implement
// BigInt(res *big.Int) (which is the case for gnark-crypto field elements)
//
// if the input is a string, it calls (big.Int).SetString(input, 0). In particular:
// The number prefix determines the actual base: A prefix of
// ”0b” or ”0B” selects base 2, ”0”, ”0o” or ”0O” selects base 8,
// and ”0x” or ”0X” selects base 16. Otherwise, the selected base is 10
// and no prefix is accepted.
//
// panics if the input is invalid
func FromInterface(input interface{}) big.Int {
	var r big.Int

	switch v := input.(type) {
	case big.Int:
		r.Set(&v)
	case *big.Int:
		r.Set(v)
	case uint8:
		r.SetUint64(uint64(v))
	case uint16:
		r.SetUint64(uint64(v))
	case uint32:
		r.SetUint64(uint64(v))
	case uint64:
		r.SetUint64(v)
	case uint:
		r.SetUint64(uint64(v))
	case int8:
		r.SetInt64(int64(v))
	case int16:
		r.SetInt64(int64(v))
	case int32:
		r.SetInt64(int64(v))
	case int64:
		r.SetInt64(int64(v))
	case int:
		r.SetInt64(int64(v))
	case string:
		if _, ok := r.SetString(v, 0); !ok {
			panic("unable to set big.Int from string " + v)
		}
	case []byte:
		r.SetBytes(v)
	default:
		if v, ok := input.(toBigIntInterface); ok {
			v.ToBigIntRegular(&r)
			return r
		} else if reflect.ValueOf(input).Kind() == reflect.Pointer {
			vv := reflect.ValueOf(input)
			if vv.CanInterface() {
				if v, ok := vv.Interface().(toBigIntInterface); ok {
					v.ToBigIntRegular(&r)
					return r
				}
			}
		}
		panic(reflect.TypeOf(input).String() + " to big.Int not supported")
	}

	return r
}
