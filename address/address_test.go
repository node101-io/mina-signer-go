package address

import (
	"testing"

	"github.com/node101-io/mina-signer-go/errors"
	"github.com/stretchr/testify/require"
)

const validAddress = "B62qm1Jr1w4B5E8Sp8PT6YE2ZEf7GSCkFxnA8UiBnea5Qp8z2LFtUdy"

func TestAddressMarshalUnmarshalRoundTrip(t *testing.T) {
	original := NewAddress(validAddress)

	encoded, err := original.Marshal()
	require.NoError(t, err)
	require.Len(t, encoded, 32)

	decoded := &Address{}
	err = decoded.Unmarshal(encoded)
	require.NoError(t, err)

	require.Equal(t, validAddress, decoded.addr)
}

func TestAddressUnmarshalRejectsInvalidLength(t *testing.T) {
	addr := &Address{}

	err := addr.Unmarshal([]byte{0x01, 0x02})
	require.ErrorIs(t, err, errors.ErrInvalidAddressLength)
}
func TestAddressNilAddress(t *testing.T) {

	var addr *Address

	_, err := addr.Marshal()
	require.ErrorIs(t, err, errors.ErrNilAddress)
}
