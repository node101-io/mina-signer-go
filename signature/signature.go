package signature

import (
	"fmt"
	"math/big"
)

const (
	// BigIntSize defines the byte size for each big.Int (R and S) in the signature.
	// Pallas curve field elements and scalars are ~255 bits, fitting into 32 bytes.
	BigIntSize = 32
	// TotalSignatureSize is R (32 bytes) + S (32 bytes).
	TotalSignatureSize = BigIntSize * 2
)

type Signature struct {
	R *big.Int // Field element
	S *big.Int // Scalar
}

// MarshalBinary serializes the Signature into a byte slice.
// The format is [R (32 bytes)][S (32 bytes)], totaling 64 bytes.
func (sig *Signature) MarshalBinary() ([]byte, error) {
	if sig == nil || sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("cannot marshal Signature: R or S is nil")
	}

	out := make([]byte, TotalSignatureSize)

	rBytes := sig.R.Bytes()
	if len(rBytes) > BigIntSize {
		return nil, fmt.Errorf("Signature.R is too large: got %d bytes, max %d bytes", len(rBytes), BigIntSize)
	}
	copy(out[BigIntSize-len(rBytes):BigIntSize], rBytes) // Left-pad R

	sBytes := sig.S.Bytes()
	if len(sBytes) > BigIntSize {
		return nil, fmt.Errorf("Signature.S is too large: got %d bytes, max %d bytes", len(sBytes), BigIntSize)
	}
	copy(out[BigIntSize+(BigIntSize-len(sBytes)):], sBytes) // Left-pad S into the second half

	return out, nil
}

// UnmarshalBinary deserializes data into the Signature.
// data is expected to be TotalSignatureSize (64) bytes long.
func (sig *Signature) UnmarshalBinary(data []byte) error {
	if len(data) != TotalSignatureSize {
		return fmt.Errorf("invalid data length for Signature: expected %d bytes, got %d bytes", TotalSignatureSize, len(data))
	}

	if sig.R == nil {
		sig.R = new(big.Int)
	}
	sig.R.SetBytes(data[0:BigIntSize])

	if sig.S == nil {
		sig.S = new(big.Int)
	}
	sig.S.SetBytes(data[BigIntSize:])

	return nil
}
