package curve

import (
	"go-signer/field"
	"math/big"
)

var (
	pallasGenerator = &GroupProjective{
		X: big.NewInt(1),
		Y: StrToBigInt("12418654782883325593414442427049395787963493412651469444558597405572177144507"),
		Z: big.NewInt(1),
	}
	vestaGenerator = &GroupProjective{
		X: big.NewInt(1),
		Y: StrToBigInt("11426906929455361843568202299992114520848200991084027513389447476559454104162"),
		Z: big.NewInt(1),
	}

	// Curve constants for y^2 = x^3 + ax + b
	a = big.NewInt(0)
	b = big.NewInt(5)

	projectiveZero = &GroupProjective{
		X: big.NewInt(1),
		Y: big.NewInt(1),
		Z: big.NewInt(0),
	}
)

type GroupProjective struct {
	X, Y, Z *big.Int
}

type GroupAffine struct {
	X, Y     *big.Int
	Infinity bool
}

type CurveParams struct {
	Name      string
	Modulus   *big.Int
	Order     *big.Int
	Generator *GroupProjective
	A, B      *big.Int
}

type ProjectiveCurve struct {
	CurveParams
	Field *field.FiniteField
	Zero  *GroupProjective
	One   *GroupProjective

	Equal        func(g, h *GroupProjective) bool
	IsOnCurve    func(g *GroupProjective) bool
	IsInSubgroup func(g *GroupProjective) bool
	Add          func(g, h *GroupProjective) *GroupProjective
	Double       func(g *GroupProjective) *GroupProjective
	Negate       func(g *GroupProjective) *GroupProjective
	Sub          func(g, h *GroupProjective) *GroupProjective
	Scale        func(g *GroupProjective, s *big.Int) *GroupProjective
	ToAffine     func(g *GroupProjective) GroupAffine
	FromAffine   func(a GroupAffine) *GroupProjective
}

func NewPallasCurve() *ProjectiveCurve {
	params := CurveParams{
		Name:      "Pallas",
		Modulus:   field.P,
		Order:     field.Q,
		Generator: pallasGenerator,
		A:         a,
		B:         b,
	}
	return CreateCurveProjective(params)
}

func NewVestaCurve() *ProjectiveCurve {
	params := CurveParams{
		Name:      "Vesta",
		Modulus:   field.Q,
		Order:     field.P,
		Generator: vestaGenerator,
		A:         a,
		B:         b,
	}
	return CreateCurveProjective(params)
}

func StrToBigInt(s string) *big.Int {
	n := new(big.Int)
	n.SetString(s, 0)
	return n
}

func BigIntToBits(n *big.Int) []bool {
	bits := make([]bool, 255)
	for i := 0; i < 255; i++ {
		bits[i] = n.Bit(i) == 1
	}
	return bits
}

func NegateInField(x *big.Int, p *big.Int) *big.Int {
	if x.Sign() == 0 {
		return x
	}
	return new(big.Int).Sub(p, x)
}

func ProjectiveNeg(x *GroupProjective, p *big.Int) *GroupProjective {
	return &GroupProjective{
		X: x.X,
		Y: NegateInField(x.Y, p),
		Z: x.Z,
	}
}

func ProjectiveEqual(g, h *GroupProjective, p *big.Int) bool {
	if (g.Z.Sign() == 0 || h.Z.Sign() == 0) && g.Z.Cmp(h.Z) != 0 {
		return false
	}

	var gz2 = field.Mod(new(big.Int).Mul(g.Z, g.Z), p)
	var hz2 = field.Mod(new(big.Int).Mul(h.Z, h.Z), p)

	if field.Mod(new(big.Int).Sub(
		field.Mod(new(big.Int).Mul(g.X, hz2), p),
		field.Mod(new(big.Int).Mul(h.X, gz2), p),
	), p).Sign() != 0 {
		return false
	}

	var gz3 = field.Mod(new(big.Int).Mul(g.Z, gz2), p)
	var hz3 = field.Mod(new(big.Int).Mul(h.Z, hz2), p)

	return field.Mod(new(big.Int).Mul(g.Y, hz3), p) ==
		field.Mod(new(big.Int).Mul(h.Y, gz3), p)
}

func ProjectiveOnCurve(g *GroupProjective, p, b, a *big.Int) bool {
	var x3 = field.Mod(new(big.Int).Mul(new(big.Int).Mul(g.X, g.X), g.X), p)
	var y2 = field.Mod(new(big.Int).Mul(g.Y, g.Y), p)
	var z2 = field.Mod(new(big.Int).Mul(g.Z, g.Z), p)
	var z4 = field.Mod(new(big.Int).Mul(z2, z2), p)
	var z6 = field.Mod(new(big.Int).Mul(z2, z4), p)

	// y2 - x3 - a * x * z4 - b * z6
	var lhs = field.Mod(
		new(big.Int).Sub(
			new(big.Int).Sub(
				new(big.Int).Sub(y2, x3),
				field.Mod(new(big.Int).Mul(a, new(big.Int).Mul(g.X, z4)), p),
			),
			field.Mod(new(big.Int).Mul(b, z6), p),
		),
		p,
	)

	return lhs.Sign() == 0
}

func ProjectiveScale(
	g *GroupProjective,
	x, p, a *big.Int,
) *GroupProjective {
	bits := BigIntToBits(x)
	h := projectiveZero
	for _, bit := range bits {
		if bit {
			h = ProjectiveAdd(h, g, p, a)
		}
		g = ProjectiveDouble(g, p, a)
	}
	return h
}

func ProjectiveInSubgroup(g *GroupProjective, p, order, a *big.Int) bool {
	var orderTimesG = ProjectiveScale(g, order, p, a)
	return ProjectiveEqual(orderTimesG, projectiveZero, p)
}

func ProjectiveFromAffine(a GroupAffine) *GroupProjective {
	if a.Infinity {
		return projectiveZero
	}
	return &GroupProjective{
		X: a.X,
		Y: a.Y,
		Z: big.NewInt(1),
	}
}

func ProjectiveToAffine(g *GroupProjective, p *big.Int) GroupAffine {
	z := g.Z
	if z.Sign() == 0 {
		return GroupAffine{Infinity: true}
	}
	if z.Cmp(big.NewInt(1)) == 0 {
		return GroupAffine{
			X:        g.X,
			Y:        g.Y,
			Infinity: false,
		}
	}
	zInv := field.Inverse(z, p)
	zInvSqrt := field.Mod(new(big.Int).Mul(zInv, zInv), p)
	x := field.Mod(new(big.Int).Mul(g.X, zInvSqrt), p)
	y := field.Mod(new(big.Int).Mul(g.Y, field.Mod(new(big.Int).Mul(zInv, zInvSqrt), p)), p)
	return GroupAffine{
		X:        x,
		Y:        y,
		Infinity: false,
	}
}

func ProjectiveDouble(g *GroupProjective, p, a *big.Int) *GroupProjective {
	if a.Sign() == 0 {
		return ProjectiveDoubleA0(g, p)
	}
	if new(big.Int).Add(a, big.NewInt(3)) == p {
		return ProjectiveDoubleAminus3(g, p)
	}

	panic("Projective doubling is not implemented for general curve parameter a, only a = 0 and a = -3")

}

func ProjectiveDoubleA0(g *GroupProjective, p *big.Int) *GroupProjective {
	if g.Z.Sign() == 0 {
		return g
	}
	var X1, Y1, Z1 *big.Int
	X1, Y1, Z1 = g.X, g.Y, g.Z

	if Y1.Sign() == 0 {
		panic("Unexpected point at infinity")
	}

	var A = field.Mod(new(big.Int).Mul(X1, X1), p)
	var B = field.Mod(new(big.Int).Mul(Y1, Y1), p)
	var C = field.Mod(new(big.Int).Mul(B, B), p)
	var D = field.Mod(
		new(big.Int).Mul(
			big.NewInt(2),
			new(big.Int).Sub(
				new(big.Int).Sub(
					new(big.Int).Mul(
						new(big.Int).Add(X1, B),
						new(big.Int).Add(X1, B),
					),
					A,
				),
				C,
			),
		),
		p,
	)
	var E = field.Mod(new(big.Int).Mul(big.NewInt(3), A), p)
	var F = field.Mod(new(big.Int).Mul(E, E), p)
	// X3 = F-2*D
	var X3 = field.Mod(new(big.Int).Sub(F, new(big.Int).Mul(D, big.NewInt(2))), p)
	// Y3 = E*(D-X3)-8*C
	var Y3 = field.Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(E, new(big.Int).Sub(D, X3)),
			new(big.Int).Mul(big.NewInt(8), C),
		),
		p,
	)
	// Z3 = 2*Y1*Z1
	var Z3 = field.Mod(new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(Y1, Z1)), p)
	return &GroupProjective{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func ProjectiveDoubleAminus3(g *GroupProjective, p *big.Int) *GroupProjective {
	if g.Z.Sign() == 0 {
		return g
	}
	var X1, Y1, Z1 *big.Int
	X1, Y1, Z1 = g.X, g.Y, g.Z

	if Y1.Sign() == 0 {
		panic("Unexpected point at infinity")
	}

	// delta = Z1^2
	var delta = field.Mod(new(big.Int).Mul(Z1, Z1), p)
	// gamma = Y1^2
	var gamma = field.Mod(new(big.Int).Mul(Y1, Y1), p)
	// beta = X1*gamma
	var beta = field.Mod(new(big.Int).Mul(X1, gamma), p)
	// alpha = 3*(X1-delta)*(X1+delta)
	var alpha = field.Mod(
		new(big.Int).Mul(
			big.NewInt(3),
			new(big.Int).Sub(
				new(big.Int).Add(X1, delta),
				new(big.Int).Sub(X1, delta),
			),
		),
		p,
	)
	// X3 = alpha^2-8*beta
	var X3 = field.Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(alpha, alpha),
			new(big.Int).Mul(big.NewInt(8), beta),
		),
		p,
	)
	// Z3 = (Y1+Z1)^2-gamma-delta
	var Z3 = field.Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				new(big.Int).Add(Y1, Z1),
				new(big.Int).Add(Y1, Z1),
			),
			new(big.Int).Add(gamma, delta),
		),
		p,
	)
	// Y3 = alpha*(4*beta-X3)-8*gamma^2
	var Y3 = field.Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				alpha,
				new(big.Int).Sub(
					new(big.Int).Mul(big.NewInt(4), beta),
					X3,
				),
			),
			new(big.Int).Mul(big.NewInt(8), new(big.Int).Mul(gamma, gamma)),
		),
		p,
	)
	return &GroupProjective{
		X: X3,
		Y: Y3,
		Z: Z3,
	}
}

func ProjectiveAdd(
	g, h *GroupProjective,
	p, a *big.Int,
) *GroupProjective {
	if g.Z.Sign() == 0 {
		return h
	}
	if h.Z.Sign() == 0 {
		return g
	}
	var X1, Y1, Z1, X2, Y2, Z2 *big.Int
	X1, Y1, Z1 = g.X, g.Y, g.Z
	X2, Y2, Z2 = h.X, h.Y, h.Z

	var Z1Z1 = field.Mod(new(big.Int).Mul(Z1, Z1), p)
	var Z2Z2 = field.Mod(new(big.Int).Mul(Z2, Z2), p)
	var U1 = field.Mod(new(big.Int).Mul(X1, Z2Z2), p)
	var U2 = field.Mod(new(big.Int).Mul(X2, Z1Z1), p)
	var S1 = field.Mod(new(big.Int).Mul(Y1, new(big.Int).Mul(Z2, Z2Z2)), p)
	var S2 = field.Mod(new(big.Int).Mul(Y2, new(big.Int).Mul(Z1, Z1Z1)), p)
	var H = field.Mod(new(big.Int).Sub(U2, U1), p)
	if H.Sign() == 0 {
		if S1.Cmp(S2) == 0 {
			return ProjectiveDouble(g, p, a)
		}
		if field.Mod(new(big.Int).Add(S1, S2), p).Sign() == 0 {
			return projectiveZero
		}
		panic("Invalid point")
	}

	// I = (2*H)^2
	var I = field.Mod(
		new(big.Int).Mul(
			big.NewInt(4),
			new(big.Int).Mul(H, H),
		),
		p,
	)
	// J = H*I
	var J = field.Mod(new(big.Int).Mul(H, I), p)
	// r = 2*(S2-S1)
	var R = field.Mod(new(big.Int).Mul(big.NewInt(2), new(big.Int).Sub(S2, S1)), p)
	// V = U1*I
	var V = field.Mod(new(big.Int).Mul(U1, I), p)
	// X3 = r^2-J-2*V
	var X3 = field.Mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(R, R), J), new(big.Int).Mul(big.NewInt(2), V)), p)
	// Y3 = r*(V-X3)-2*S1*J
	var Y3 = field.Mod(new(big.Int).Sub(new(big.Int).Mul(R, new(big.Int).Sub(V, X3)), new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(S1, J))), p)
	// Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
	var Z3 = field.Mod(
		new(big.Int).Mul(
			new(big.Int).Sub(
				new(big.Int).Mul(
					new(big.Int).Add(Z1, Z2),
					new(big.Int).Add(Z1, Z2),
				),
				new(big.Int).Add(Z1Z1, Z2Z2),
			),
			H,
		),
		p,
	)
	return &GroupProjective{
		X: X3,
		Y: Y3,
		Z: Z3,
	}

}

func CreateCurveProjective(params CurveParams) *ProjectiveCurve {
	curve := &ProjectiveCurve{
		CurveParams: params,
	}
	curve.Field = field.Fp

	curve.Equal = func(g, h *GroupProjective) bool {
		return ProjectiveEqual(g, h, params.Modulus)
	}

	curve.IsOnCurve = func(g *GroupProjective) bool {
		return ProjectiveOnCurve(g, params.Modulus, params.B, params.A)
	}

	curve.IsInSubgroup = func(g *GroupProjective) bool {
		return ProjectiveInSubgroup(g, params.Modulus, params.Order, params.A)
	}

	curve.Add = func(g, h *GroupProjective) *GroupProjective {
		return ProjectiveAdd(g, h, params.Modulus, params.A)
	}

	curve.Double = func(g *GroupProjective) *GroupProjective {
		return ProjectiveDouble(g, params.Modulus, params.A)
	}

	curve.Negate = func(g *GroupProjective) *GroupProjective {
		return ProjectiveNeg(g, params.Modulus)
	}

	curve.Sub = func(g, h *GroupProjective) *GroupProjective {
		return ProjectiveAdd(g, ProjectiveNeg(h, params.Modulus), params.Modulus, params.A)
	}

	curve.Scale = func(g *GroupProjective, s *big.Int) *GroupProjective {
		// println("Scale g:", g.X.String(), g.Y.String(), g.Z.String())
		// println("Scale s:", s.String())
		// println("Scale p:", params.Modulus.String())
		// println("Scale a:", params.A.String())

		bits := BigIntToBits(s)
		h := &GroupProjective{X: big.NewInt(1), Y: big.NewInt(1), Z: big.NewInt(0)}
		tmp := &GroupProjective{X: g.X, Y: g.Y, Z: g.Z}
		for _, bit := range bits {
			if bit {
				h = ProjectiveAdd(h, tmp, params.Modulus, params.A)
			}
			tmp = ProjectiveDouble(tmp, params.Modulus, params.A)
			// println("h:", h.X.String(), h.Y.String(), h.Z.String())
			// println("tmp:", tmp.X.String(), tmp.Y.String(), tmp.Z.String())
		}
		return h
	}

	curve.ToAffine = func(g *GroupProjective) GroupAffine {
		return ProjectiveToAffine(g, params.Modulus)
	}

	curve.FromAffine = func(a GroupAffine) *GroupProjective {
		return ProjectiveFromAffine(a)
	}

	curve.Zero = &GroupProjective{X: big.NewInt(1), Y: big.NewInt(1), Z: big.NewInt(0)}
	curve.One = &GroupProjective{X: params.Generator.X, Y: params.Generator.Y, Z: big.NewInt(1)}

	return curve
}
