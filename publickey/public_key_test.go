package publickey_test

import (
	"encoding/hex"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	privatekey "github.com/node101-io/mina-signer-go/privatekey"
	"github.com/node101-io/mina-signer-go/publickey"
	localsignature "github.com/node101-io/mina-signer-go/signature"
	"github.com/stretchr/testify/require"
)

var validPrivateKeyBytes = [32]byte{
	0x3a, 0x7f, 0x1c, 0x92, 0xe4, 0x55, 0x8b, 0xd1,
	0x6f, 0x20, 0xa9, 0x3c, 0x77, 0x4e, 0x11, 0x5d,
	0x88, 0xca, 0x02, 0xf6, 0x9b, 0x31, 0x44, 0x7a,
	0xde, 0x63, 0x19, 0xaf, 0x0c, 0x5e, 0xb2, 0x90,
}

const messageToSign string = "mina-signer-go"

func TestPublicKey(t *testing.T) {

	privKey, err := privatekey.NewPrivateKeyFromBytes(validPrivateKeyBytes, mina.MainNet)
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

func TestDecodePublicKeyRejectsInvalidBytes(t *testing.T) {
	pk, err := publickey.NewPublicKeyFromBytes([]byte{0x01, 0x02}, mina.MainNet)
	require.Nil(t, pk)
	require.Error(t, err)
}

func TestDecodePublicKeyPreservesNetworkID(t *testing.T) {
	rawPublicKey, _, _ := referenceFixture(t, mina.TestNet, messageToSign)

	pk, err := publickey.NewPublicKeyFromBytes(rawPublicKey, mina.TestNet)
	require.NoError(t, err)
	require.Equal(t, mina.TestNet, pk.NetworkID())
}

func TestPublicKeyGetAndString(t *testing.T) {
	rawPublicKey, pk, _ := referenceFixture(t, mina.MainNet, messageToSign)

	pkValue, err := pk.Bytes()
	require.NoError(t, err)
	require.NotNil(t, pkValue)

	require.Equal(t, rawPublicKey, pkValue)
	require.Equal(t, hex.EncodeToString(pkValue), pk.String())
}

func TestPublicKeyVerifyReturnsErrNilSignature(t *testing.T) {
	_, pk, _ := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := pk.Verify(nil, messageToSign)
	require.False(t, validity)
	require.ErrorIs(t, err, publickey.ErrNilSignature)
}

func TestPublicKeyVerifyAcceptsValidSignature(t *testing.T) {
	_, pk, sig := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := pk.Verify(sig, messageToSign)
	require.NoError(t, err)
	require.True(t, validity)
}

func TestPublicKeyVerifyRejectsWrongMessage(t *testing.T) {
	_, pk, sig := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := pk.Verify(sig, "different-message")
	require.False(t, validity)
	require.Error(t, err)
}

func TestPublicKeyVerifyRejectsMalformedSignature(t *testing.T) {
	_, pk, _ := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := pk.Verify(localsignature.NewSignatureFromBytes([]byte{0x01}), messageToSign)
	require.False(t, validity)
	require.Error(t, err)
}

func TestPublicKeyVerifyRejectsMismatchedNetwork(t *testing.T) {
	rawPublicKey, _, sig := referenceFixture(t, mina.MainNet, messageToSign)

	testnetPublicKey, err := publickey.NewPublicKeyFromBytes(rawPublicKey, mina.TestNet)
	require.NoError(t, err)

	validity, err := testnetPublicKey.Verify(sig, messageToSign)
	require.False(t, validity)
	require.Error(t, err)
}

func referenceFixture(t *testing.T, networkID mina.NetworkID, message string) ([]byte, *publickey.PublicKey, *localsignature.Signature) {
	t.Helper()

	scalar, err := pasta.NewPallasScalarField().FromBytes(validPrivateKeyBytes[:])
	require.NoError(t, err)

	privKey, err := mina.NewPrivateKey(scalar)
	require.NoError(t, err)

	scheme, err := mina.NewScheme(networkID, privKey)
	require.NoError(t, err)

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	signer, err := scheme.Signer(privKey)
	require.NoError(t, err)

	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	serialized, err := mina.SerializeSignature(sig)
	require.NoError(t, err)

	rawPublicKey := privKey.PublicKey().Value().Bytes()

	pk, err := publickey.NewPublicKeyFromBytes(rawPublicKey, networkID)
	require.NoError(t, err)

	return rawPublicKey, pk, localsignature.NewSignatureFromBytes(serialized)
}
