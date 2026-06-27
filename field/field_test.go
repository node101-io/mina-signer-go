package field

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	localerrors "github.com/node101-io/mina-signer-go/errors"
	"github.com/stretchr/testify/require"
)

func TestFieldFromBytesRoundTrip(t *testing.T) {
	raw := pasta.NewPallasBaseField().FromUint64(42)

	got, err := NewField().FromBytes(raw.Bytes())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.IsValid())
	require.Equal(t, raw.Bytes(), got.Bytes())
}

func TestFieldElementBytesReturnsClone(t *testing.T) {
	element := NewField().FromUint64(42)
	require.NotNil(t, element)

	original := element.Bytes()
	require.NotNil(t, original)

	mutated := element.Bytes()
	require.NotNil(t, mutated)
	mutated[0] ^= 0xff

	require.Equal(t, original, element.Bytes())
}

func TestFieldElementCloneIsIndependent(t *testing.T) {
	element := NewField().FromUint64(42)
	require.NotNil(t, element)

	clone := element.Clone()
	require.NotNil(t, clone)
	require.True(t, clone.IsValid())
	require.True(t, element.Equal(clone))

	require.NotSame(t, element, clone)
	require.NotSame(t, element.element, clone.element)
}

func TestNilFieldMethodsAreSafe(t *testing.T) {
	var f *Field

	require.Equal(t, 0, f.ElementSize())
	require.Nil(t, f.Zero())
	require.Nil(t, f.One())
	require.Nil(t, f.FromUint64(42))

	_, err := f.FromBytes([]byte{1, 2, 3})
	require.ErrorIs(t, err, localerrors.ErrNilField)

	_, err = f.FromBytesBEReduce([]byte{1, 2, 3})
	require.ErrorIs(t, err, localerrors.ErrNilField)
}

func TestFieldElementStringReturnsDecimalValue(t *testing.T) {
	element := NewField().FromUint64(42)
	require.NotNil(t, element)
	require.Equal(t, "42", element.String())
}
