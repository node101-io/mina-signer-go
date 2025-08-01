package keys

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/base58"
	"github.com/node101-io/mina-signer-go/curve"
	"github.com/node101-io/mina-signer-go/curvebigint"
	"github.com/node101-io/mina-signer-go/field"
	"github.com/node101-io/mina-signer-go/poseidonbigint"
	"github.com/node101-io/mina-signer-go/signature"
)

const (
	// PublicKeyXByteSize defines the byte size for the X coordinate of a PublicKey.
	// Pallas curve field elements are approximately 255 bits, fitting into 32 bytes.
	PublicKeyXByteSize = 32
	// PublicKeyIsOddByteSize defines the byte size for the IsOdd flag.
	PublicKeyIsOddByteSize = 1
	// PublicKeyTotalByteSize is the total size of a marshaled PublicKey.
	PublicKeyTotalByteSize = PublicKeyXByteSize + PublicKeyIsOddByteSize
)

// PublicKey represents a public key with an X coordinate and a boolean indicating if Y is odd.
type PublicKey struct {
	X     *big.Int `json:"x" protobuf:"bytes,1,opt,name=x,proto3"`
	IsOdd bool     `json:"isOdd" protobuf:"varint,2,opt,name=isOdd,proto3"`
}

// HashInputLegacy is a legacy structure used for hashing PublicKey.
// It might be specific to certain older hashing schemes.
type HashInputLegacy struct {
	Fields []*big.Int
	Bits   []bool
}

// IsValid checks if the PublicKey is a valid point on the Pallas curve.
func (pk *PublicKey) IsValid() bool {
	curveB := curve.NewPallasCurve().B
	xCubed := field.Mod(new(big.Int).Mul(pk.X, new(big.Int).Mul(pk.X, pk.X)), field.P)
	ySquared := field.Mod(new(big.Int).Add(xCubed, curveB), field.P)
	return field.IsSquare(ySquared, field.P)
}

// Point represents a point on the curve with X and Y coordinates.
// TODO: This is a temporary stand-in for curvebigint.Group or curve.GroupAffine.
//
//	Decide on a canonical Group/Point type and use it.
type Point struct {
	X *big.Int
	Y *big.Int
}

// ToGroup reconstructs the full curve point (Group) from a compressed PublicKey.
// It returns an error if the x-coordinate is invalid.
func (pk *PublicKey) ToGroup() (Point, error) {
	x := pk.X
	x2 := field.Fp.Mul(x, x)
	x3 := field.Fp.Mul(x2, x)
	ySquared := field.Fp.Add(x3, curve.NewPallasCurve().B)
	y := field.Fp.Sqrt(ySquared)
	if y == nil {
		// Original code panics here. Consider returning an error instead for robust handling.
		panic("PublicKey.ToGroup: invalid x coordinate")
	}
	yIsOdd := y.Bit(0) == 1
	if pk.IsOdd != yIsOdd {
		y = field.Fp.Negate(y)
	}
	return Point{X: x, Y: y}, nil
}

// PublicKeyFromPoint creates a PublicKey from a curve Point (X, Y coordinates).
func PublicKeyFromPoint(p Point) PublicKey {
	return PublicKey{
		X:     p.X,
		IsOdd: isOdd(p.Y), // isOdd is an internal helper
	}
}

// Equal checks if two PublicKeys are identical.
func (pk *PublicKey) Equal(other PublicKey) bool {
	if pk.X == nil && other.X == nil {
		return pk.IsOdd == other.IsOdd
	}
	if pk.X == nil || other.X == nil {
		return false // One is nil, the other is not.
	}
	return pk.X.Cmp(other.X) == 0 && pk.IsOdd == other.IsOdd
}

// ToInputLegacy converts the PublicKey to a legacy format for hashing.
func (pk *PublicKey) ToInputLegacy() HashInputLegacy {
	return HashInputLegacy{Fields: []*big.Int{pk.X}, Bits: []bool{pk.IsOdd}}
}

// MarshalBytes serializes the PublicKey into a byte slice.
// The format is [X (PublicKeyXByteSize bytes)][IsOdd (PublicKeyIsOddByteSize byte)], totaling PublicKeyTotalByteSize bytes.
func (pk *PublicKey) MarshalBytes() ([]byte, error) {
	if pk == nil || pk.X == nil {
		return nil, fmt.Errorf("cannot marshal PublicKey: pk or pk.X is nil")
	}

	out := make([]byte, PublicKeyTotalByteSize)

	xBytes := pk.X.Bytes()
	if len(xBytes) > PublicKeyXByteSize {
		return nil, fmt.Errorf("PublicKey.X is too large: got %d bytes, max %d bytes", len(xBytes), PublicKeyXByteSize)
	}
	offset := PublicKeyXByteSize - len(xBytes)
	copy(out[offset:PublicKeyXByteSize], xBytes)

	if pk.IsOdd {
		out[PublicKeyXByteSize] = 0x01
	} else {
		out[PublicKeyXByteSize] = 0x00
	}

	return out, nil
}

// UnmarshalBytes deserializes data into the PublicKey.
// data is expected to be PublicKeyTotalByteSize bytes long.
func (pk *PublicKey) UnmarshalBytes(data []byte) error {
	if len(data) != PublicKeyTotalByteSize {
		return fmt.Errorf("invalid data length for PublicKey: expected %d bytes, got %d bytes", PublicKeyTotalByteSize, len(data))
	}

	if pk.X == nil {
		pk.X = new(big.Int)
	}
	pk.X.SetBytes(data[0:PublicKeyXByteSize])

	isOddByte := data[PublicKeyXByteSize] // Accessing the byte after X part
	if isOddByte == 0x01 {
		pk.IsOdd = true
	} else if isOddByte == 0x00 {
		pk.IsOdd = false
	} else {
		return fmt.Errorf("invalid byte for IsOdd flag: expected 0x00 or 0x01, got 0x%02x", isOddByte)
	}

	return nil
}

// MarshalJSON implements the json.Marshaler interface for PublicKey.
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	// Guard against nil pk.X if it can occur, as pk.X.String() would panic.
	var xStr string
	if pk.X != nil {
		xStr = pk.X.String()
	}
	return json.Marshal(struct {
		X     string `json:"x"`
		IsOdd bool   `json:"isOdd"`
	}{
		X:     xStr,
		IsOdd: pk.IsOdd,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for PublicKey.
func (pk *PublicKey) UnmarshalJSON(data []byte) error {
	var temp struct {
		X     string `json:"x"`
		IsOdd bool   `json:"isOdd"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	x := new(big.Int)
	if temp.X != "" { // Handle case where X might be an empty string in JSON
		var success bool
		x, success = new(big.Int).SetString(temp.X, 10)
		if !success {
			return fmt.Errorf("failed to parse X '%s' from JSON for PublicKey", temp.X)
		}
	} else {
		// Decide how to handle empty X string: treat as nil, zero, or error.
		// Assuming nil for now if X can be legitimately nil.
		x = nil
	}
	pk.X = x
	pk.IsOdd = temp.IsOdd
	return nil
}

// isOdd is an internal helper function to check if a big.Int is odd.
// It safely handles nil inputs, returning false.
func isOdd(x *big.Int) bool {
	if x == nil {
		return false
	}
	return x.Bit(0) == 1
}

// Verify checks a Schnorr signature against the public key and message.
// It uses helper functions from the keys package (hashMessage).
func (pk PublicKey) Verify(sig *signature.Signature, message poseidonbigint.HashInput, networkId string) bool {
	if pk.X == nil || sig == nil || sig.R == nil || sig.S == nil {
		// TODO: Log error or handle more gracefully? For now, mimic original behavior of just returning false.
		return false
	}

	// 1. Convert public key to a point (group element)
	pkPoint, err := pk.ToGroup() // pkPoint is keys.Point
	if err != nil {
		return false // If public key can't be converted to a point, verification fails
	}

	// 2. Calculate e = Hash(message || pubKey_x || pubKey_y || R_x)
	// hashMessage expects keys.Point
	e := hashMessage(message, pkPoint, sig.R, networkId)

	// 3. Calculate R' = sG - eP
	//    sG = s * G (NewPallasCurve().One is G)
	//    eP = e * pkGroup (pkPoint needs to be in projective form for scaling)

	// Convert pkPoint (keys.Point which is affine-like) to curve.GroupProjective for scaling
	// curvebigint.Group is also affine-like. We need GroupToProjective.
	// Create a temporary curvebigint.Group from pkPoint to use GroupToProjective
	pkCurveBigintGroup := curvebigint.Group{X: pkPoint.X, Y: pkPoint.Y}
	pkProjective := curvebigint.GroupToProjective(pkCurveBigintGroup)

	pallas := curve.NewPallasCurve()
	sG := pallas.Scale(pallas.One, sig.S) // sG is GroupProjective
	eP := pallas.Scale(pkProjective, e)   // eP is GroupProjective

	rPrimeProjective := pallas.Sub(sG, eP) // rPrimeProjective is GroupProjective

	// 4. Convert R' back to affine and check if R'_x == R and R'_y is even.
	rPrimeAffine, err := curvebigint.GroupFromProjective(rPrimeProjective) // rPrimeAffine is curvebigint.Group
	if err != nil {
		return false // If R' is infinity or other error
	}

	rxPrime, ryPrime := rPrimeAffine.X, rPrimeAffine.Y

	// Check R'_x == R (sig.R)
	return field.Fp.IsEven(ryPrime) && (rxPrime.Cmp(sig.R) == 0)
}

// VerifyFieldElement checks a Schnorr signature for a single field element message.
func (pk PublicKey) VerifyFieldElement(sig *signature.Signature, message *big.Int, networkId string) bool {
	msgInput := poseidonbigint.HashInput{
		Fields: []*big.Int{message},
	}
	return pk.Verify(sig, msgInput, networkId)
}

func (pk PublicKey) ToAddress() (string, error) {
	pkBytes, err := pk.MarshalBytes()
	if err != nil {
		return "", err
	}

	// Encode the public key bytes to base58
	address := base58.Encode(pkBytes)

	return address, nil
}

func (pk PublicKey) FromAddress(address string) (PublicKey, error) {
	pkBytes := base58.Decode(address)

	if err := pk.UnmarshalBytes(pkBytes); err != nil {
		return PublicKey{}, err
	}

	return pk, nil
}

// VerifyMessage checks a Schnorr signature against an arbitrary string message.
// The message is split into field elements whose byte length equals the base field size.
// After constructing a poseidonbigint.HashInput from these elements, it delegates to Verify.
func (pk PublicKey) VerifyMessage(sig *signature.Signature, msg string, networkId string) bool {
	// Determine the chunk size (in bytes) for each field element.
	chunkSize := field.Fp.SizeInBytes()

	msgBytes := []byte(msg)

	// Convert the message into field elements for Poseidon hash.
	var fields []*big.Int
	if len(msgBytes) == 0 {
		fields = []*big.Int{}
	} else {
		for i := 0; i < len(msgBytes); i += chunkSize {
			end := i + chunkSize
			if end > len(msgBytes) {
				end = len(msgBytes)
			}
			chunk := msgBytes[i:end]

			fieldElement := new(big.Int)
			fieldElement.SetBytes(chunk)
			fields = append(fields, fieldElement)
		}
	}

	hashInput := poseidonbigint.HashInput{
		Fields: fields,
	}

	return pk.Verify(sig, hashInput, networkId)
}
