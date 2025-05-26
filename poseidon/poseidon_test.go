package poseidon

import (
	"go-signer/constants"
	"go-signer/field"
	"math/big"
	"testing"
)

func TestPoseidonHash(t *testing.T) {
	poseidon := CreatePoseidon(*field.Fp, constants.PoseidonParamsKimchiFp)
	input := []*big.Int{big.NewInt(0)}
	hashResult := poseidon.Hash(input)
	// fmt.Println("Poseidon hash result:", hashResult.String())

	expected, _ := new(big.Int).SetString("21565680844461314807147611702860246336805372493508489110556896454939225549736", 10)

	if hashResult.Cmp(expected) != 0 {
		t.Errorf("Poseidon hash failed: got %s, expected %s", hashResult.String(), expected.String())
	}

	input2 := []*big.Int{big.NewInt(0), big.NewInt(1)}
	hashResult2 := poseidon.Hash(input2)
	// fmt.Println("Poseidon hash result for input2:", hashResult2.String())

	expected2, _ := new(big.Int).SetString("25153834528238352025091411039949114579843839670440790727153524232958326376354", 10)

	if hashResult2.Cmp(expected2) != 0 {
		t.Errorf("Poseidon hash failed for input2: got %s, expected %s", hashResult2.String(), expected2.String())
	}
}
