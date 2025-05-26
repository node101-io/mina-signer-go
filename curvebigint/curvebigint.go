package curvebigint

import (
	"encoding/json"
	"errors"
	"go-signer/curve"
	"go-signer/field"
	"math/big"
)

type Group struct {
	X *big.Int
	Y *big.Int
}

type PublicKey struct {
	X     *big.Int
	IsOdd bool
}

type Scalar = *big.Int
type PrivateKey = *big.Int

// Convert affine to projective
func GroupToProjective(g Group) *curve.GroupProjective {
	return curve.ProjectiveFromAffine(curve.GroupAffine{
		X:        g.X,
		Y:        g.Y,
		Infinity: false,
	})
}

// Convert projective to affine (throws if at infinity)
func GroupFromProjective(gp *curve.GroupProjective) (Group, error) {
	affine := curve.ProjectiveToAffine(gp, field.P)
	if affine.Infinity {
		return Group{}, errors.New("Group.fromProjective: point is infinity")
	}
	return Group{X: affine.X, Y: affine.Y}, nil
}

// func GeneratorMina() Group {
// 	genAff := curve.ProjectiveToAffine(curve.NewPallasCurve().One, field.P)
// 	return Group{X: genAff.X, Y: genAff.Y}
// }

func GeneratorMina() Group {
	c := curve.NewPallasCurve()
	// println("c.One:", c.One)
	if c.One == nil {
		panic("curve.One is nil!")
	}
	aff := curve.ProjectiveToAffine(c.One, field.P)
	// println("aff.X:", aff.X, "aff.Y:", aff.Y, "aff.Infinity:", aff.Infinity)
	if aff.Infinity {
		panic("Generator affine is at infinity!")
	}
	return Group{X: aff.X, Y: aff.Y}
}

func GroupScale(g Group, scalar *big.Int) Group {
	gProj := curve.ProjectiveFromAffine(curve.GroupAffine{
		X:        g.X,
		Y:        g.Y,
		Infinity: false,
	})

	resProj := curve.NewPallasCurve().Scale(gProj, scalar)

	resAff := curve.ProjectiveToAffine(resProj, field.P)
	// println("resAff.X:", resAff.X.String())
	// println("resAff.Y:", resAff.Y.String())
	return Group{X: resAff.X, Y: resAff.Y}
}

// Get curve b parameter
func GroupB() *big.Int {
	return curve.NewPallasCurve().B
}

// y^2 = x^3 + b mod p
func IsValidPublicKey(x *big.Int) bool {
	curveB := GroupB()
	xCubed := field.Mod(new(big.Int).Mul(x, new(big.Int).Mul(x, x)), field.P)
	ySquared := field.Mod(new(big.Int).Add(xCubed, curveB), field.P)
	return field.IsSquare(ySquared, field.P)
}

// Reconstruct Group from compressed (x, isOdd)
func PublicKeyToGroup(pk PublicKey) Group {
	x := pk.X
	x2 := field.Fp.Mul(x, x)
	x3 := field.Fp.Mul(x2, x)
	ySquared := field.Fp.Add(x3, curve.NewPallasCurve().B)
	y := field.Fp.Sqrt(ySquared)
	if y == nil {
		panic("PublicKeyToGroup: invalid x coordinate")
	}
	yIsOdd := y.Bit(0) == 1
	if pk.IsOdd != yIsOdd {
		y = field.Fp.Negate(y)
	}
	return Group{X: x, Y: y}
}

func PublicKeyFromGroup(g Group) PublicKey {
	return PublicKey{
		X:     g.X,
		IsOdd: isOdd(g.Y),
	}
}

// Equality
func PublicKeyEqual(a, b PublicKey) bool {
	return a.X.Cmp(b.X) == 0 && a.IsOdd == b.IsOdd
}

// To legacy input
type HashInputLegacy struct {
	Fields []*big.Int
	Bits   []bool
}

func PublicKeyToInputLegacy(pk PublicKey) HashInputLegacy {
	return HashInputLegacy{Fields: []*big.Int{pk.X}, Bits: []bool{pk.IsOdd}}
}

// JSON serialization (Base58 methods would be added here)
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		X     string `json:"x"`
		IsOdd bool   `json:"isOdd"`
	}{
		X:     pk.X.String(),
		IsOdd: pk.IsOdd,
	})
}
func (pk *PublicKey) UnmarshalJSON(data []byte) error {
	var temp struct {
		X     string `json:"x"`
		IsOdd bool   `json:"isOdd"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	x, _ := new(big.Int).SetString(temp.X, 10)
	pk.X = x
	pk.IsOdd = temp.IsOdd
	return nil
}

func PrivateKeyToPublicKey(sk PrivateKey) PublicKey {
	pk := GroupScale(GeneratorMina(), sk)
	return PublicKeyFromGroup(pk)
}

func isOdd(x *big.Int) bool {
	return x.Bit(0) == 1
}
