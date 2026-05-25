package signature_test

import (
	"encoding/hex"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	signaturesdk "github.com/node101-io/mina-signer-go/signature"
	"github.com/stretchr/testify/require"
)

var ValidEncodedSig string = "fe3f451da33c28f1561c43be4dd9df50518b8f9b2128f26712eae57de3c0211f26becbe775facc626b6bd8a5c5a0cb183fed214242111d52954079cdb9f33c14"

func TestDecodeSignatureGetAndString(t *testing.T) {

	decodedSig, err := hex.DecodeString(ValidEncodedSig)
	require.NoError(t, err)
	require.NotNil(t, decodedSig)

	sig, err := signaturesdk.NewSignatureFromBytes(decodedSig)
	require.NotNil(t, sig)
	require.NoError(t, err)

	require.Equal(t, decodedSig, sig.Bytes())
	require.Equal(t, hex.EncodeToString(decodedSig), sig.String())
}

func TestSizeMatchesBronMina(t *testing.T) {
	require.Equal(t, mina.SignatureSize, signaturesdk.Size())
}
