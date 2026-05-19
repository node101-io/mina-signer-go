package poseidon_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	minaposeidon "github.com/node101-io/mina-signer-go/poseidon"
	"github.com/stretchr/testify/require"
)

const prefix string = "pulsar"

type TestVector struct {
	Input  []string `json:"input"`
	Output string   `json:"output"`
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func ReadTestVectorsFile(path string) ([]TestVector, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vectors []TestVector

	dec := json.NewDecoder(f)
	if err := dec.Decode(&vectors); err != nil {
		return nil, err
	}

	return vectors, nil
}

func TestPoseidonHashVectors(t *testing.T) {

	poseidon := minaposeidon.NewPoseidon()

	hasher, err := poseidon.GetHasher()
	require.NoError(t, err)
	require.NotNil(t, hasher)

	vector, err := ReadTestVectorsFile("test_vectors.json")
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

func TestHashDivisibleByBronRate(t *testing.T) {

	b := make([]byte, 64)

	_, err := rand.Read(b)
	require.NoError(t, err)

	poseidon := minaposeidon.NewPoseidon()

	hash, err := poseidon.Hash(b)
	require.NoError(t, err)
	require.NotNil(t, hash)

}
func TestHashNotDivisibleByBronRate(t *testing.T) {

	b := make([]byte, 65)

	_, err := rand.Read(b)
	require.NoError(t, err)

	poseidon := minaposeidon.NewPoseidon()

	hash, err := poseidon.Hash(b)
	require.NoError(t, err)
	require.NotNil(t, hash)

}
