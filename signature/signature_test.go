package signature_test

import (
	"encoding/hex"
	"testing"

	signaturesdk "github.com/node101-io/mina-signer-go/signature"
	"github.com/stretchr/testify/require"
)

var ValidEncodedSig string = "fe3f451da33c28f1561c43be4dd9df50518b8f9b2128f26712eae57de3c0211f26becbe775facc626b6bd8a5c5a0cb183fed214242111d52954079cdb9f33c14"

func TestSignatureBytesRoundTrip(t *testing.T) {
	rawSig, err := hex.DecodeString(ValidEncodedSig)
	require.NoError(t, err)

	originalSig, err := signaturesdk.NewSignatureFromBytes(rawSig)
	require.NoError(t, err)
	require.NotNil(t, originalSig)

	serialized := originalSig.Bytes()
	roundTripSig, err := signaturesdk.NewSignatureFromBytes(serialized)
	require.NoError(t, err)
	require.NotNil(t, roundTripSig)

	require.Equal(t, originalSig.Bytes(), roundTripSig.Bytes())
}
