package keys

import (
	"crypto/sha256"
	"errors" // For Sign method
	"fmt"
	"math/big"

	"github.com/node101-io/mina-signer-go/curvebigint"    // For GroupScale and GeneratorMina
	"github.com/node101-io/mina-signer-go/field"          // For Fp, Fq operations in Sign
	"github.com/node101-io/mina-signer-go/poseidonbigint" // For HashInput type
	"github.com/node101-io/mina-signer-go/signature"      // For returning *signature.Signature
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

// NewPrivateKeyFromBytes creates a new PrivateKey from a 32-byte array.
// This is typically used with SHA256 hash outputs.
// If the value exceeds the field order or is zero, it re-hashes the input
// until a valid private key is found within the field range.
func NewPrivateKeyFromBytes(data [32]byte) PrivateKey {
	// Convert byte array to big.Int
	value := new(big.Int).SetBytes(data[:])

	// Current hash data to work with
	currentData := data

	// Keep hashing until we get a value that's both non-zero and within field order
	for {
		// Apply modulo operation to ensure value is within the scalar field
		value = field.Fq.Mod(value)

		// If we get a valid non-zero value, use it
		if value.Cmp(big.NewInt(0)) != 0 {
			break
		}

		// If value is zero, hash the current data again and try again
		currentData = sha256.Sum256(currentData[:])
		value = new(big.Int).SetBytes(currentData[:])
	}

	return PrivateKey{Value: value}
}

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

// Sign generates a Schnorr signature for the given message input.
// It uses helper functions from the keys package (deriveNonce, hashMessage).
func (sk PrivateKey) Sign(message poseidonbigint.HashInput, networkId string) (*signature.Signature, error) {
	if sk.Value == nil {
		return nil, errors.New("cannot sign with a nil private key value")
	}

	// 1. Derive the public key point corresponding to this private key.
	// ToPublicKey() returns keys.PublicKey, then ToGroup() returns keys.Point and an error.
	// Note: ToPublicKey internally uses curvebigint.GroupScale and GeneratorMina.
	pubKey := sk.ToPublicKey()
	publicKeyPoint, err := pubKey.ToGroup() // publicKeyPoint is keys.Point
	if err != nil {
		// This might happen if pubKey.X is such that Sqrt results in nil (invalid point)
		// which shouldn't occur if the private key is valid and ToPublicKey works correctly.
		return nil, fmt.Errorf("failed to get public key point for signing: %w", err)
	}

	// 2. Derive nonce (k')
	kPrime := deriveNonce(message, publicKeyPoint, sk.Value, networkId)
	if kPrime.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("sign: derived nonce kPrime is 0")
	}

	// 3. Calculate R = k' * G
	// We need curvebigint.GroupScale and GeneratorMina for this.
	rGroupPoint := curvebigint.GroupScale(curvebigint.GeneratorMina(), kPrime) // rGroupPoint is curvebigint.Group
	rx := rGroupPoint.X
	ry := rGroupPoint.Y

	// 4. Adjust k based on R_y's parity
	k := new(big.Int).Set(kPrime)
	if !field.Fp.IsEven(ry) { // field.Fp must be accessible or this op moved to a place with access
		k = field.Fq.Negate(kPrime)
	}

	// 5. Calculate  e = Hash(message || pubKey_x || pubKey_y || R_x)
	// hashMessage expects keys.Point for the public key part.
	e := hashMessage(message, publicKeyPoint, rx, networkId)

	// 6. Calculate s = k + e * priv
	sVal := field.Fq.Add(k, field.Fq.Mul(e, sk.Value))

	return &signature.Signature{R: rx, S: sVal}, nil
}

// SignFieldElement generates a Schnorr signature for a single field element message.
func (sk PrivateKey) SignFieldElement(message *big.Int, networkId string) (*signature.Signature, error) {
	msgInput := poseidonbigint.HashInput{
		Fields: []*big.Int{message},
	}
	return sk.Sign(msgInput, networkId)
}

// Equal checks if two PrivateKeys are identical.
func (sk PrivateKey) Equal(other PrivateKey) bool {
	// If both values are nil
	if sk.Value == nil && other.Value == nil {
		return true
	}
	// If one value is nil, the other is not
	if sk.Value == nil || other.Value == nil {
		return false
	}
	// If both values are non-nil, compare them
	return sk.Value.Cmp(other.Value) == 0
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
