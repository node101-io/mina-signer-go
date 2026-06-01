package merklelist

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/stretchr/testify/require"
)

const o1jsAlignmentVectorFile string = "../testdata/poseidon/o1js_alignment_vectors.json"

const prefix string = "pulsar"

var arbitraryDataToHash = []byte("arbitrary-data-to-hash")

type o1jsAlignmentVectors struct {
	O1JSVersion string             `json:"o1jsVersion"`
	MerkleLists []merkleListVector `json:"merkleLists"`
}

type merkleListVector struct {
	Name            string   `json:"name"`
	Prefix          string   `json:"prefix"`
	ElementsDecimal []string `json:"elementsDecimal"`
	RootDecimal     string   `json:"rootDecimal"`
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

func TestMerkleListMatchesO1JS(t *testing.T) {
	vectors := readO1JSAlignmentVectors(t)

	for _, vector := range vectors.MerkleLists {
		t.Run(vector.Name, func(t *testing.T) {
			merkleList := NewMerkleList(vector.Prefix)

			for _, decimal := range vector.ElementsDecimal {
				err := merkleList.Append(pallasFieldFromDecimal(t, decimal).Bytes())
				require.NoError(t, err)
			}

			require.Equal(t, vector.RootDecimal, pallasFieldDecimalFromBytes(t, merkleList.Root()))
		})
	}
}

func TestNewMerkleListFromRootDefaultsEmptyRootToZero(t *testing.T) {

	newList, err := NewMerkleListFromRoot(prefix, nil)
	require.NoError(t, err)
	require.NotNil(t, newList)
	require.Equal(t, pasta.NewPallasBaseField().Zero().Bytes(), newList.Root())

}
func TestCompareNewMerkleAndFromRoot(t *testing.T) {

	original := NewMerkleList(prefix)
	original.Append([]byte("append"))

	newList, err := NewMerkleListFromRoot(prefix, original.Root())
	require.NoError(t, err)
	require.NotNil(t, newList)

	original.Append(arbitraryDataToHash)
	newList.Append(arbitraryDataToHash)
	require.Equal(t, original.root, newList.Root())
}
