package poseidon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/node101-io/mina-signer-go/errors"
	"github.com/stretchr/testify/require"
)

type testVector struct {
	Input  []string `json:"input"`
	Output string   `json:"output"`
}

const prefix string = "pulsar"
const officialPoseidonVectorFile string = "../testdata/poseidon/official_vectors.json"
const o1jsAlignmentVectorFile string = "../testdata/poseidon/o1js_alignment_vectors.json"

type o1jsAlignmentVectors struct {
	O1JSVersion          string                     `json:"o1jsVersion"`
	HashWithPrefixBytes  []hashWithPrefixByteVector `json:"hashWithPrefixBytes"`
	HashFieldsWithPrefix []hashFieldsVector         `json:"hashFieldsWithPrefix"`
}

type hashWithPrefixByteVector struct {
	Name          string `json:"name"`
	Prefix        string `json:"prefix"`
	InputHex      string `json:"inputHex"`
	OutputDecimal string `json:"outputDecimal"`
}

type hashFieldsVector struct {
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`
	FieldsDecimal []string `json:"fieldsDecimal"`
	OutputDecimal string   `json:"outputDecimal"`
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func readTestVectorsFile(path string) ([]testVector, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vectors []testVector

	dec := json.NewDecoder(f)
	if err := dec.Decode(&vectors); err != nil {
		return nil, err
	}

	return vectors, nil
}

func readO1JSAlignmentVectors(t *testing.T) o1jsAlignmentVectors {
	t.Helper()

	f, err := os.Open(o1jsAlignmentVectorFile)
	require.NoError(t, err)
	defer f.Close()

	var vectors o1jsAlignmentVectors
	dec := json.NewDecoder(f)
	require.NoError(t, dec.Decode(&vectors))
	require.Equal(t, "2.9.0", vectors.O1JSVersion)

	return vectors
}

func pallasFieldFromDecimal(t *testing.T, decimal string) *pasta.PallasBaseFieldElement {
	t.Helper()

	n, ok := new(big.Int).SetString(decimal, 10)
	require.True(t, ok, "invalid decimal field: %s", decimal)

	field := pasta.NewPallasBaseField()
	b := n.Bytes()
	require.LessOrEqual(t, len(b), field.ElementSize())

	fixed := make([]byte, field.ElementSize())
	copy(fixed[len(fixed)-len(b):], b)

	element, err := field.FromBytes(fixed)
	require.NoError(t, err)
	return element
}

func pallasFieldDecimalFromBytes(t *testing.T, data []byte) string {
	t.Helper()

	field, err := pasta.NewPallasBaseField().FromBytes(data)
	require.NoError(t, err)
	return field.String()
}

func TestPoseidonHashVectors(t *testing.T) {

	poseidon := NewPoseidon()

	hasher := poseidon.hasher
	require.NotNil(t, hasher)

	vector, err := readTestVectorsFile(officialPoseidonVectorFile)
	require.NoError(t, err)
	require.NotNil(t, vector)

	for _, vect := range vector {

		hasher.Reset()

		inputs := make([]*pasta.PallasBaseFieldElement, 0, len(vect.Input))

		for _, input := range vect.Input {

			msg, err := hex.DecodeString(input)
			require.NoError(t, err)
			require.NotNil(t, msg)

			hashField, err := pasta.NewPallasBaseField().FromBytes(reverseBytes(msg))
			require.NoError(t, err)
			require.NotNil(t, hashField)

			inputs = append(inputs, hashField)
		}

		for len(inputs)%hasher.Rate() != 0 {
			inputs = append(inputs, pasta.NewPallasBaseField().Zero())
		}

		err = hasher.Update(inputs...)
		require.NoError(t, err)

		hash := hasher.Digest()
		encoded := hex.EncodeToString(reverseBytes(hash.Bytes()))

		require.Equal(t, vect.Output, encoded)
	}

}

func TestPoseidonHashWithPrefixMatchesO1JS(t *testing.T) {
	vectors := readO1JSAlignmentVectors(t)

	for _, vector := range vectors.HashWithPrefixBytes {
		t.Run(vector.Name, func(t *testing.T) {
			input, err := hex.DecodeString(vector.InputHex)
			require.NoError(t, err)

			poseidon := NewPoseidon()
			hash, err := poseidon.HashWithPrefix(vector.Prefix, input)
			require.NoError(t, err)
			require.NotNil(t, hash)

			require.Equal(t, vector.OutputDecimal, pallasFieldDecimalFromBytes(t, hash))
		})
	}
}

func TestPoseidonHashFieldsWithPrefixMatchesO1JS(t *testing.T) {
	vectors := readO1JSAlignmentVectors(t)

	for _, vector := range vectors.HashFieldsWithPrefix {
		t.Run(vector.Name, func(t *testing.T) {
			fields := make([]*pasta.PallasBaseFieldElement, 0, len(vector.FieldsDecimal))
			for _, decimal := range vector.FieldsDecimal {
				fields = append(fields, pallasFieldFromDecimal(t, decimal))
			}

			poseidon := NewPoseidon()
			hash, err := poseidon.HashFieldsWithPrefix(vector.Prefix, fields...)
			require.NoError(t, err)
			require.NotNil(t, hash)

			require.Equal(t, vector.OutputDecimal, pallasFieldDecimalFromBytes(t, hash))
		})
	}
}

func TestHashDivisibleByBronRate(t *testing.T) {

	b := make([]byte, 64)

	_, err := rand.Read(b)
	require.NoError(t, err)

	poseidon := NewPoseidon()

	hash, err := poseidon.Hash(b)
	require.NoError(t, err)
	require.NotNil(t, hash)

}
func TestHashNotDivisibleByBronRate(t *testing.T) {

	b := make([]byte, 65)

	_, err := rand.Read(b)
	require.NoError(t, err)

	poseidon := NewPoseidon()

	hash, err := poseidon.Hash(b)
	require.NoError(t, err)
	require.NotNil(t, hash)

}

func TestHashReturnsErrNilPoseidon(t *testing.T) {
	var poseidon *Poseidon

	hash, err := poseidon.Hash([]byte("message"))
	require.Nil(t, hash)
	require.ErrorIs(t, err, errors.ErrNilPoseidon)
}

func TestHashResetsDirtyHasherState(t *testing.T) {
	input := []byte("message")

	cleanPoseidon := NewPoseidon()
	expected, err := cleanPoseidon.Hash(input)
	require.NoError(t, err)

	dirtyPoseidon := NewPoseidon()
	field := pasta.NewPallasBaseField()
	dirtyInputs := make([]*pasta.PallasBaseFieldElement, dirtyPoseidon.hasher.Rate())
	dirtyInputs[0] = field.FromUint64(42)
	for i := 1; i < len(dirtyInputs); i++ {
		dirtyInputs[i] = field.Zero()
	}

	err = dirtyPoseidon.hasher.Update(dirtyInputs...)
	require.NoError(t, err)

	actual, err := dirtyPoseidon.Hash(input)
	require.NoError(t, err)
	require.Equal(t, expected, actual)

	actual, err = dirtyPoseidon.Hash(input)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
