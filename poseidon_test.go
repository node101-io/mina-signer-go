package minasignergo

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

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
