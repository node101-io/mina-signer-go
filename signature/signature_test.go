package signature_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	privatekey "github.com/node101-io/mina-signer-go/privateKey"
	"github.com/stretchr/testify/require"
)

var hardcodedPriv = [32]byte{
	0x3a, 0x7f, 0x1c, 0x92, 0xe4, 0x55, 0x8b, 0xd1,
	0x6f, 0x20, 0xa9, 0x3c, 0x77, 0x4e, 0x11, 0x5d,
	0x88, 0xca, 0x02, 0xf6, 0x9b, 0x31, 0x44, 0x7a,
	0xde, 0x63, 0x19, 0xaf, 0x0c, 0x5e, 0xb2, 0x90,
}

const messageToSign string = "mina-signer-go"

func TestPublicKey(t *testing.T) {

	privKey, err := privatekey.NewPrivateKeyFromBytes(hardcodedPriv, mina.MainNet)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	sig, err := privKey.Sign(messageToSign)
	require.NoError(t, err)
	require.NotNil(t, sig)

	public, err := privKey.ToPublicKey()
	require.NoError(t, err)
	require.NotNil(t, public)

	validity, err := public.Verify(sig, messageToSign)
	require.NoError(t, err)
	require.True(t, validity)

}
