package schnorr

import (
	"errors"
	"fmt"
	"github.com/node101-io/mina-signer-go/constants"
	"github.com/node101-io/mina-signer-go/curve"
	"github.com/node101-io/mina-signer-go/curvebigint"
	"github.com/node101-io/mina-signer-go/field"
	"github.com/node101-io/mina-signer-go/hashgeneric"
	"github.com/node101-io/mina-signer-go/poseidon"
	"github.com/node101-io/mina-signer-go/poseidonbigint"
	"github.com/node101-io/mina-signer-go/scalar"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2b"
)

var (
	networkIdMainnet = big.NewInt(0x01)
	networkIdDevnet  = big.NewInt(0x00)
)

type Signature struct {
	R *big.Int // Field element
	S *big.Int // Scalar
}

func SignFieldElement(message *big.Int, priv *big.Int, networkId string) (*Signature, error) {
	msg := poseidonbigint.HashInput{
		Fields: []*big.Int{message},
	}
	return Sign(msg, priv, networkId)
}

func VerifyFieldElement(sig *Signature, message *big.Int, pub curvebigint.PublicKey, networkId string) bool {
	msg := poseidonbigint.HashInput{
		Fields: []*big.Int{message},
	}
	return Verify(sig, msg, pub, networkId)
}

func Sign(message poseidonbigint.HashInput, priv *big.Int, networkId string) (*Signature, error) {
	publicKey := curvebigint.GroupScale(curvebigint.GeneratorMina(), priv)
	// println("s:", priv.String())
	kPrime := DeriveNonce(message, publicKey, priv, networkId)
	if kPrime.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("sign: derived nonce is 0")
	}
	// println("kPrime:", kPrime.String())

	RGroup := curvebigint.GroupScale(curvebigint.GeneratorMina(), kPrime)
	// println("RGroup.X:", RGroup.X.String())
	// println("RGroup.Y:", RGroup.Y.String())
	rx := RGroup.X
	ry := RGroup.Y

	k := new(big.Int).Set(kPrime)
	if !field.Fp.IsEven(ry) {
		k = field.Fq.Negate(kPrime)
	}
	// println("k:", k.String())

	e := HashMessage(message, publicKey, rx, networkId)
	// println("e:", e.String())
	s := field.Fq.Add(k, field.Fq.Mul(e, priv))
	// println("s:", s.String())
	return &Signature{R: rx, S: s}, nil
}

func Verify(sig *Signature, message poseidonbigint.HashInput, pub curvebigint.PublicKey, networkId string) bool {
	r, s := sig.R, sig.S
	pk := curvebigint.PublicKeyToGroup(pub)
	e := HashMessage(message, pk, r, networkId)

	S1 := curve.NewPallasCurve().Scale(curve.NewPallasCurve().One, s)
	S2 := curve.NewPallasCurve().Scale(curvebigint.GroupToProjective(pk), e)
	R := curve.NewPallasCurve().Sub(S1, S2)
	Raff, error := curvebigint.GroupFromProjective(R)
	if error != nil {
		return false
	}
	rx, ry := Raff.X, Raff.Y
	return field.Fp.IsEven(ry) && (rx.Cmp(r) == 0)
}

func BigIntsToString(a []*big.Int) string {
	var parts []string
	for _, x := range a {
		if x != nil {
			parts = append(parts, x.String())
		} else {
			parts = append(parts, "nil")
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func PackedFieldsToString(p []poseidonbigint.PackedField) string {
	var parts []string
	for _, pf := range p {
		parts = append(parts, fmt.Sprintf("{Field:%s Size:%d}", pf.Field.String(), pf.Size))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func BoolsToString(b []bool) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i, v := range b {
		if v {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
		if i < len(b)-1 {
			sb.WriteByte(',')
		}
	}
	sb.WriteString("]")
	return sb.String()
}

func DeriveNonce(message poseidonbigint.HashInput, publicKey curvebigint.Group, priv *big.Int, networkId string) *big.Int {
	x, y := publicKey.X, publicKey.Y
	d := field.FromBigInt(priv)
	idx, idy := GetNetworkIdHashInput(networkId)
	// fmt.Println("DERIVE NONCE")
	// fmt.Printf("idx: %s\nidy: %d\n", idx.String(), idy)
	helper := poseidonbigint.HashInputHelpers{}
	input := helper.Append(message, poseidonbigint.HashInput{
		Fields: []*big.Int{x, y, d},
		Packed: []poseidonbigint.PackedField{
			{Field: idx, Size: idy},
		},
	})
	// fmt.Printf("input.Fields: %s\n", BigIntsToString(input.Fields))
	// fmt.Printf("input.Packed: %s\n", PackedFieldsToString(input.Packed))

	packedInput := poseidonbigint.PackToFields(input)
	// fmt.Printf("packedInput: %s\n", BigIntsToString(packedInput))

	var inputBits []bool
	for _, f := range packedInput {
		bits := curve.BigIntToBits(f)
		inputBits = append(inputBits, bits...)
	}
	// fmt.Printf("inputBits: %s\n", BoolsToString(inputBits))
	inputBytes := BitsToBytes(inputBits)
	// fmt.Printf("inputBytes: %v\n", inputBytes)
	bytes := Blake2b256(inputBytes)
	// fmt.Printf("bytes: %v\n", bytes)
	bytes[31] &= 0x3f
	// fmt.Printf("bytes After: %v\n", bytes)
	result := scalar.ScalarFromBytes(bytes).BigInt()
	// fmt.Printf("kPrime: %s\n", result.String())
	return result
}

func HashMessage(message poseidonbigint.HashInput, pub curvebigint.Group, r *big.Int, networkId string) *big.Int {
	x, y := pub.X, pub.Y
	helper := poseidonbigint.HashInputHelpers{}
	hashGeneric := hashgeneric.CreateHashHelpers(field.Fp, poseidon.CreatePoseidon(*field.Fp, constants.PoseidonParamsKimchiFp))
	input := helper.Append(message, poseidonbigint.HashInput{Fields: []*big.Int{x, y, r}})
	// println("networkId:", networkId)
	prefix := SignaturePrefix(networkId)
	// println("PREFIX:", prefix)
	// fmt.Printf("input.Fields: %s\n", BigIntsToString(input.Fields))
	return hashGeneric.HashWithPrefix(prefix, poseidonbigint.PackToFields(input))
}

func GetNetworkIdHashInput(network string) (*big.Int, int) {
	switch network {
	case "mainnet":
		return networkIdMainnet, 8
	case "devnet", "testnet":
		return networkIdDevnet, 8
	default:
		return NetworkIdOfString(network)
	}
}

func NetworkIdOfString(n string) (*big.Int, int) {
	l := len(n)
	acc := ""
	for i := l - 1; i >= 0; i-- {
		b := n[i]
		padded := NumberToBytePadded(int(b))
		acc += padded
	}
	val, _ := new(big.Int).SetString("0b"+acc, 0)
	return val, len(acc)
}

func NumberToBytePadded(b int) string {
	return leftPad(strconv.FormatInt(int64(b), 2), "0", 8)
}

func leftPad(s, pad string, length int) string {
	for len(s) < length {
		s = pad + s
	}
	return s
}

func SignaturePrefix(network string) string {
	switch network {
	case "mainnet":
		return constants.Prefixes["signatureMainnet"]
	case "devnet", "testnet":
		return constants.Prefixes["signatureTestnet"]
	default:
		return CreateCustomPrefix(network + "Signature")
	}
}

func CreateCustomPrefix(prefix string) string {
	const maxLength = 20
	const paddingChar = "*"
	length := len(prefix)
	if length <= maxLength {
		diff := maxLength - length
		return prefix + strings.Repeat(paddingChar, diff)
	} else {
		return prefix[:maxLength]
	}
}

func BitsToBytes(bits []bool) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b {
			out[i/8] |= 1 << (uint(i) % 8)
		}
	}
	return out
}

func Blake2b256(data []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(data)
	return h.Sum(nil)
}
