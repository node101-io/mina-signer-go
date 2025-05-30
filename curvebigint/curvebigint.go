package curvebigint

import (
	"errors"
	"github.com/node101-io/mina-signer-go/curve"
	"github.com/node101-io/mina-signer-go/field"
	"math/big"
)

type Group struct {
	X *big.Int
	Y *big.Int
}

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

func GeneratorMina() Group {
	c := curve.NewPallasCurve()
	if c.One == nil {
		panic("curve.One is nil!")
	}
	aff := curve.ProjectiveToAffine(c.One, field.P)
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
	return Group{X: resAff.X, Y: resAff.Y}
}

// Get curve b parameter
func GroupB() *big.Int {
	return curve.NewPallasCurve().B
}
