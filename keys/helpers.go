package keys

import (
	"math/big"
	"strconv"
	"strings"

	"github.com/node101-io/mina-signer-go/constants"
	"github.com/node101-io/mina-signer-go/curve"

	"github.com/node101-io/mina-signer-go/field"
	"github.com/node101-io/mina-signer-go/hashgeneric"
	"github.com/node101-io/mina-signer-go/poseidon"
	"github.com/node101-io/mina-signer-go/poseidonbigint"
	"github.com/node101-io/mina-signer-go/scalar"

	"golang.org/x/crypto/blake2b"
)

var (
	// These are unexported and used internally by helper functions.
	networkIdMainnet = big.NewInt(0x01)
	networkIdDevnet  = big.NewInt(0x00)
)

// deriveNonce derives a nonce for Schnorr signature generation.
// It takes the message, the public key point (as keys.Point), the private key value, and network ID.
func deriveNonce(message poseidonbigint.HashInput, publicKeyPoint Point, privValue *big.Int, networkId string) *big.Int {
	x, y := publicKeyPoint.X, publicKeyPoint.Y // Using X, Y from keys.Point
	d := field.FromBigInt(privValue)
	idx, idy := getNetworkIdHashInput(networkId)

	helper := poseidonbigint.HashInputHelpers{}
	input := helper.Append(message, poseidonbigint.HashInput{
		Fields: []*big.Int{x, y, d},
		Packed: []poseidonbigint.PackedField{
			{Field: idx, Size: idy},
		},
	})

	packedInput := poseidonbigint.PackToFields(input)

	var inputBits []bool
	for _, f := range packedInput {
		// curve.BigIntToBits is a public function from an imported package, so it can be used.
		bits := curve.BigIntToBits(f)
		inputBits = append(inputBits, bits...)
	}
	inputBytes := bitsToBytes(inputBits)
	bytes := blake2b256(inputBytes)
	bytes[31] &= 0x3f // Clear the top two bits

	// scalar.ScalarFromBytes is a public function
	result := scalar.ScalarFromBytes(bytes).BigInt()
	return result
}

// hashMessage computes the hash used in Schnorr signature, combining the message, public key, and a nonce component (r).
// It takes the message, public key point (as keys.Point), the R value of the signature, and network ID.
func hashMessage(message poseidonbigint.HashInput, pubPoint Point, r_val *big.Int, networkId string) *big.Int {
	x, y := pubPoint.X, pubPoint.Y // Using X, Y from keys.Point
	helper := poseidonbigint.HashInputHelpers{}
	// poseidon.CreatePoseidon and constants.PoseidonParamsKimchiFp are public
	hashGeneric := hashgeneric.CreateHashHelpers(field.Fp, poseidon.CreatePoseidon(*field.Fp, constants.PoseidonParamsKimchiFp))
	input := helper.Append(message, poseidonbigint.HashInput{Fields: []*big.Int{x, y, r_val}})

	prefix := signaturePrefix(networkId)
	// hashGeneric.HashWithPrefix is a public method of the hashGeneric helper instance.
	return hashGeneric.HashWithPrefix(prefix, poseidonbigint.PackToFields(input))
}

// -- Helper functions for network ID and prefixes (mostly as they were, made unexported) --

func getNetworkIdHashInput(network string) (*big.Int, int) {
	switch network {
	case "mainnet":
		return networkIdMainnet, 8
	case "devnet", "testnet":
		return networkIdDevnet, 8
	default:
		return networkIdOfString(network)
	}
}

func networkIdOfString(n string) (*big.Int, int) {
	l := len(n)
	acc := ""
	for i := l - 1; i >= 0; i-- {
		b := n[i]
		padded := numberToBytePadded(int(b))
		acc += padded
	}
	val, _ := new(big.Int).SetString("0b"+acc, 0) // Error ignored as in original
	return val, len(acc)
}

func numberToBytePadded(b int) string {
	return leftPad(strconv.FormatInt(int64(b), 2), "0", 8)
}

func leftPad(s, pad string, length int) string {
	for len(s) < length {
		s = pad + s
	}
	return s
}

func signaturePrefix(network string) string {
	switch network {
	case "mainnet":
		return constants.Prefixes["signatureMainnet"]
	case "devnet", "testnet":
		return constants.Prefixes["signatureTestnet"]
	default:
		// constants.CreateCustomPrefix was not defined, assuming it was a typo for CreateCustomPrefix in signature pkg
		// For now, let's use the local createCustomPrefix
		return createCustomPrefix(network + "Signature")
	}
}

// This was originally in signature.go, moved here and made unexported.
func createCustomPrefix(prefix string) string {
	const maxLength = 20    // Keep this internal to the helper
	const paddingChar = "*" // Keep this internal
	length := len(prefix)
	if length <= maxLength {
		diff := maxLength - length
		return prefix + strings.Repeat(paddingChar, diff)
	} else {
		return prefix[:maxLength]
	}
}

// -- Byte manipulation helpers (mostly as they were, made unexported) --

func bitsToBytes(bits []bool) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b {
			out[i/8] |= 1 << (uint(i) % 8)
		}
	}
	return out
}

func blake2b256(data []byte) []byte {
	h, _ := blake2b.New256(nil) // Error ignored as in original
	h.Write(data)
	return h.Sum(nil)
}
