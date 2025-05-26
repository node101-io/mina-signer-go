package scalar

import (
	"crypto/rand"
	"errors"
	"go-signer/field"
	"math/big"
)

type Scalar struct {
	n *big.Int
}

var (
	Q = field.Q
)

func NewScalar(x any) *Scalar {
	var v *big.Int
	switch t := x.(type) {
	case *big.Int:
		v = new(big.Int).Set(t)
	case int:
		v = big.NewInt(int64(t))
	case int64:
		v = big.NewInt(t)
	case uint64:
		v = new(big.Int).SetUint64(t)
	case string:
		v, _ = new(big.Int).SetString(t, 10)
	case Scalar:
		v = new(big.Int).Set(t.n)
	case *Scalar:
		v = new(big.Int).Set(t.n)
	default:
		panic("unsupported type for Scalar")
	}
	return &Scalar{n: field.Mod(v, Q)}
}

func RandomScalar() (*Scalar, error) {
	bytes := make([]byte, Q.BitLen()/8+8)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(bytes)
	n.Mod(n, Q)
	return &Scalar{n: n}, nil
}

func (s *Scalar) BigInt() *big.Int {
	return new(big.Int).Set(s.n)
}

func (s *Scalar) Add(y *Scalar) *Scalar {
	return &Scalar{n: field.Mod(new(big.Int).Add(s.n, y.n), Q)}
}
func (s *Scalar) Sub(y *Scalar) *Scalar {
	return &Scalar{n: field.Mod(new(big.Int).Sub(s.n, y.n), Q)}
}
func (s *Scalar) Mul(y *Scalar) *Scalar {
	return &Scalar{n: field.Mod(new(big.Int).Mul(s.n, y.n), Q)}
}
func (s *Scalar) Neg() *Scalar {
	return &Scalar{n: field.Mod(new(big.Int).Neg(s.n), Q)}
}
func (s *Scalar) Div(y *Scalar) (*Scalar, error) {
	yInv := new(big.Int).ModInverse(y.n, Q)
	if yInv == nil {
		return nil, errors.New("division by zero or not invertible")
	}
	return &Scalar{n: field.Mod(new(big.Int).Mul(s.n, yInv), Q)}, nil
}

func ScalarFromBytes(bs []byte) *Scalar {

	rev := make([]byte, len(bs))
	for i, b := range bs {
		rev[len(bs)-1-i] = b
	}
	n := new(big.Int).SetBytes(rev)
	return &Scalar{n: field.Mod(n, Q)}
}

func (s *Scalar) Bytes() []byte {
	return s.n.Bytes()
}

func ScalarFromBits(bits []bool) *Scalar {
	n := big.NewInt(0)
	for i, bit := range bits {
		if bit {
			n.SetBit(n, i, 1)
		}
	}
	return &Scalar{n: field.Mod(n, Q)}
}
