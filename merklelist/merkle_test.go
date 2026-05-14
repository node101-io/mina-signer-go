package merkle

import (
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/stretchr/testify/require"
)

const prefix string = "pulsar"

func TestMerkleList(t *testing.T) {
	merkleList, err := NewMerkleList(prefix)
	require.NoError(t, err)

	field := pasta.NewPallasBaseField()

	for i := 1; i <= 10; i++ {
		err := merkleList.Append(field.FromUint64(uint64(i)).Bytes())
		require.NoError(t, err)
	}

	rootField, err := field.FromBytes(merkleList.Root())
	require.NoError(t, err)

	fmt.Println(rootField.String())
}
