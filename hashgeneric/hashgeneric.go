package hashgeneric

import (
	"github.com/node101-io/mina-signer-go/poseidon"
	"math/big"
)

func StringToBytes(s string) []byte {
	return []byte(s)
}

type GenericSignableField interface {
	SizeInBytes() int
	FromBytes([]byte) *big.Int
}

func PrefixToField(field GenericSignableField, prefix string) *big.Int {
	fieldSize := field.SizeInBytes()
	if len(prefix) >= fieldSize {
		panic("prefix too long")
	}
	stringBytes := StringToBytes(prefix)
	padded := append(stringBytes, make([]byte, fieldSize-len(stringBytes))...)
	// fmt.Println("padded:", padded)
	// fmt.Println("field:", field.FromBytes(padded))
	return field.FromBytes(padded)
}

type HashHelpers struct {
	Salt                func(prefix string) []*big.Int
	EmptyHashWithPrefix func(prefix string) *big.Int
	HashWithPrefix      func(prefix string, input []*big.Int) *big.Int
}

func CreateHashHelpers(field GenericSignableField, poseidon *poseidon.Poseidon) HashHelpers {
	salt := func(prefix string) []*big.Int {
		fields := []*big.Int{PrefixToField(field, prefix)}
		// println("fields:", fields[0].String())
		return poseidon.Update(poseidon.InitialState(), fields)
	}
	emptyHashWithPrefix := func(prefix string) *big.Int {
		return salt(prefix)[0]
	}
	hashWithPrefix := func(prefix string, input []*big.Int) *big.Int {
		init := salt(prefix)
		// println("init:", init[0].String(), init[1].String(), init[2].String())
		// println("input:", input[0].String(), input[1].String(), input[2].String(), input[3].String())
		return poseidon.Update(init, input)[0]
	}
	return HashHelpers{
		Salt:                salt,
		EmptyHashWithPrefix: emptyHashWithPrefix,
		HashWithPrefix:      hashWithPrefix,
	}
}
