package field

import (
	"crypto/rand"
	"math/big"
)

var (
	P, _ = new(big.Int).SetString("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)
	Q, _ = new(big.Int).SetString("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16)

	PMinusOneOddFactor, _ = new(big.Int).SetString("40000000000000000000000000000000224698fc094cf91b992d30ed", 16)
	QMinusOneOddFactor, _ = new(big.Int).SetString("40000000000000000000000000000000224698fc0994a8dd8c46eb21", 16)

	TwoadicRootFp, _ = new(big.Int).SetString("2bce74deac30ebda362120830561f81aea322bf2b7bb7584bdad6fabd87ea32f", 16)
	TwoadicRootFq, _ = new(big.Int).SetString("2de6a9b8746d3f589e5c4dfd492ae26e9bb97ea3c106f049a70e2c1102b6d05f", 16)
)

func Mod(x, p *big.Int) *big.Int {
	z := new(big.Int).Mod(x, p)
	if z.Sign() < 0 {
		z.Add(z, p)
	}
	return z
}

func Power(a, n, p *big.Int) *big.Int {
	a = Mod(a, p)
	result := big.NewInt(1)
	base := new(big.Int).Set(a)
	exp := new(big.Int).Set(n)
	for exp.Sign() > 0 {
		if exp.Bit(0) == 1 {
			result = Mod(new(big.Int).Mul(result, base), p)
		}
		base = Mod(new(big.Int).Mul(base, base), p)
		exp.Rsh(exp, 1)
	}
	return result
}

func Inverse(a, p *big.Int) *big.Int {
	a = Mod(a, p)
	if a.Sign() == 0 {
		return nil
	}
	var b = new(big.Int).Set(p)
	var x, y = big.NewInt(0), big.NewInt(1)
	var u, v = big.NewInt(1), big.NewInt(0)
	for a.Sign() != 0 {
		q := new(big.Int).Div(b, a)
		r := new(big.Int).Mod(b, a)
		m := new(big.Int).Sub(x, new(big.Int).Mul(u, q))
		n := new(big.Int).Sub(y, new(big.Int).Mul(v, q))
		b.Set(a)
		a.Set(r)
		x.Set(u)
		y.Set(v)
		u.Set(m)
		v.Set(n)
	}
	if b.Cmp(big.NewInt(1)) != 0 {
		return nil
	}
	return Mod(x, p)
}

func Sqrt(n, p, Q, c, M *big.Int) *big.Int {
	n = Mod(n, p)
	if n.Sign() == 0 {
		return big.NewInt(0)
	}
	t := Power(n, new(big.Int).Sub(Q, big.NewInt(1)).Rsh(Q, 1), p)
	R := Mod(new(big.Int).Mul(t, n), p)
	t = Mod(new(big.Int).Mul(t, R), p)

	one := big.NewInt(1)
	for {
		if t.Cmp(one) == 0 {
			return R
		}
		i := big.NewInt(0)
		s := new(big.Int).Set(t)
		for s.Cmp(one) != 0 {
			s = Mod(new(big.Int).Mul(s, s), p)
			i.Add(i, one)
		}
		if i.Cmp(M) == 0 {
			return nil
		}
		exp := new(big.Int).Sub(M, i)
		exp.Sub(exp, one)
		b := Power(c, new(big.Int).Lsh(one, uint(exp.Int64())), p)
		M = i
		c = Mod(new(big.Int).Mul(b, b), p)
		t = Mod(new(big.Int).Mul(t, c), p)
		R = Mod(new(big.Int).Mul(R, b), p)
	}
}

func IsSquare(x, p *big.Int) bool {
	x = Mod(x, p)
	if x.Sign() == 0 {
		return true
	}
	exp := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	sqrt1 := Power(x, exp, p)
	return sqrt1.Cmp(big.NewInt(1)) == 0
}

func RandomField(p *big.Int, sizeInBytes int, hiBitMask byte) *big.Int {
	for {
		bytes := make([]byte, sizeInBytes)
		_, _ = rand.Read(bytes)
		bytes[sizeInBytes-1] &= hiBitMask
		x := BytesToBigInt(bytes)
		if x.Cmp(p) < 0 {
			return x
		}
	}
}

func BytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func Log2(n *big.Int) int {
	return n.BitLen()
}

type FiniteField struct {
	Modulus     *big.Int
	SizeInBits  int
	T           *big.Int
	M           *big.Int
	TwoadicRoot *big.Int

	Mod      func(x *big.Int) *big.Int
	Add      func(x, y *big.Int) *big.Int
	Sub      func(x, y *big.Int) *big.Int
	Mul      func(x, y *big.Int) *big.Int
	Negate   func(x *big.Int) *big.Int
	Square   func(x *big.Int) *big.Int
	Inverse  func(x *big.Int) *big.Int
	IsSquare func(x *big.Int) bool
	Sqrt     func(x *big.Int) *big.Int
	Power    func(x, n *big.Int) *big.Int
	Equal    func(x, y *big.Int) bool
	IsEven   func(x *big.Int) bool
	Random   func() *big.Int
}

func NewFiniteField(p, oddFactor, twoadicRoot, twoadicity *big.Int) *FiniteField {
	sizeInBits := Log2(p)
	sizeInBytes := (sizeInBits + 7) / 8
	sizeHighestByte := sizeInBits - 8*(sizeInBytes-1)
	hiBitMask := byte((1 << sizeHighestByte) - 1)
	return &FiniteField{
		Modulus:     p,
		SizeInBits:  sizeInBits,
		T:           oddFactor,
		M:           twoadicity,
		TwoadicRoot: twoadicRoot,
		Mod: func(x *big.Int) *big.Int {
			return Mod(x, p)
		},
		Add: func(x, y *big.Int) *big.Int {
			return Mod(new(big.Int).Add(x, y), p)
		},
		Sub: func(x, y *big.Int) *big.Int {
			return Mod(new(big.Int).Sub(x, y), p)
		},
		Mul: func(x, y *big.Int) *big.Int {
			return Mod(new(big.Int).Mul(x, y), p)
		},
		Negate: func(x *big.Int) *big.Int {
			if x.Sign() == 0 {
				return big.NewInt(0)
			}
			return Mod(new(big.Int).Neg(x), p)
		},
		Square: func(x *big.Int) *big.Int {
			return Mod(new(big.Int).Mul(x, x), p)
		},
		Inverse: func(x *big.Int) *big.Int {
			return Inverse(x, p)
		},
		IsSquare: func(x *big.Int) bool {
			return IsSquare(x, p)
		},
		Sqrt: func(x *big.Int) *big.Int {
			// Provide Q, c, M for Tonelli-Shanks
			return Sqrt(x, p, oddFactor, twoadicRoot, twoadicity)
		},
		Power: func(x, n *big.Int) *big.Int {
			return Power(x, n, p)
		},
		Equal: func(x, y *big.Int) bool {
			return Mod(x, p).Cmp(Mod(y, p)) == 0
		},
		IsEven: func(x *big.Int) bool {
			return Mod(x, p).Bit(0) == 0
		},
		Random: func() *big.Int {
			return RandomField(p, sizeInBytes, hiBitMask)
		},
	}
}

func FromBigInt(x *big.Int) *big.Int {
	return Mod(x, P)
}

func (f *FiniteField) SizeInBytes() int {
	return int((f.SizeInBits + 7) / 8)
}

func (f *FiniteField) FromBytes(bs []byte) *big.Int {

	rev := make([]byte, len(bs))
	for i, b := range bs {
		rev[len(bs)-1-i] = b
	}
	x := new(big.Int).SetBytes(rev)
	return f.Mod(x)
}

var (
	Fp = NewFiniteField(P, PMinusOneOddFactor, TwoadicRootFp, big.NewInt(32))
	Fq = NewFiniteField(Q, QMinusOneOddFactor, TwoadicRootFq, big.NewInt(32))
)
