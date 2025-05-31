package keys

import (
	"fmt"
	"math/big"

	"github.com/node101-io/mina-signer-go/curvebigint" // For GroupScale and GeneratorMina
)

const (
	// PrivateKeyByteSize defines the byte size for a PrivateKey.
	// Pallas curve scalars are approximately 255 bits, fitting into 32 bytes.
	PrivateKeyByteSize = 32 // Public
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

// MarshalBytes serializes the PrivateKey into a byte slice.
// The format is [Value (PrivateKeyByteSize bytes)].
func (sk *PrivateKey) MarshalBytes() ([]byte, error) {
	if sk == nil || sk.Value == nil {
		return nil, fmt.Errorf("cannot marshal PrivateKey: sk or sk.Value is nil")
	}

	out := make([]byte, PrivateKeyByteSize)

	valueBytes := sk.Value.Bytes()
	if len(valueBytes) > PrivateKeyByteSize {
		return nil, fmt.Errorf("PrivateKey.Value is too large: got %d bytes, max %d bytes", len(valueBytes), PrivateKeyByteSize)
	}
	offset := PrivateKeyByteSize - len(valueBytes)
	copy(out[offset:PrivateKeyByteSize], valueBytes)

	return out, nil
}

// UnmarshalBytes deserializes data into the PrivateKey.
// data is expected to be PrivateKeyByteSize bytes long.
func (sk *PrivateKey) UnmarshalBytes(data []byte) error {
	if len(data) != PrivateKeyByteSize {
		return fmt.Errorf("invalid data length for PrivateKey: expected %d bytes, got %d bytes", PrivateKeyByteSize, len(data))
	}

	if sk.Value == nil {
		sk.Value = new(big.Int)
	}
	sk.Value.SetBytes(data)

	return nil
}
