package keys

import (
	"math/big"

	"github.com/node101-io/mina-signer-go/curvebigint" // For GroupScale and GeneratorMina
)

// PrivateKey wraps a big.Int to represent a private key.
type PrivateKey struct {
	Value *big.Int
}

// Scalar is an alias for *big.Int, typically used for scalar multiplication in cryptographic operations.
type Scalar = *big.Int

// ToPublicKey derives the corresponding PublicKey from the PrivateKey.
// It uses GeneratorMina and GroupScale from the curvebigint package.
func (sk PrivateKey) ToPublicKey() PublicKey {
	// 1. Get the generator point from curvebigint.
	genGroup := curvebigint.GeneratorMina() // This is of type curvebigint.Group

	// 2. Scale the generator by the private key's value.
	// sk.Value is the *big.Int for scalar multiplication.
	pkGroup := curvebigint.GroupScale(genGroup, sk.Value) // This is also of type curvebigint.Group

	// 3. Convert the resulting curvebigint.Group to keys.Point.
	//    keys.Point and curvebigint.Group share the same structure (X, Y *big.Int).
	pointForPublicKey := Point{X: pkGroup.X, Y: pkGroup.Y}

	// 4. Create a PublicKey from the point.
	return PublicKeyFromPoint(pointForPublicKey)
} 