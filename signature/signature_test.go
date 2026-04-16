package signature_test

import (
	"encoding/hex"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/publickey"
	"github.com/node101-io/mina-signer-go/signature"
	signaturesdk "github.com/node101-io/mina-signer-go/signature"
	"github.com/stretchr/testify/require"
)

var hardcodedPriv = [32]byte{
	0x3a, 0x7f, 0x1c, 0x92, 0xe4, 0x55, 0x8b, 0xd1,
	0x6f, 0x20, 0xa9, 0x3c, 0x77, 0x4e, 0x11, 0x5d,
	0x88, 0xca, 0x02, 0xf6, 0x9b, 0x31, 0x44, 0x7a,
	0xde, 0x63, 0x19, 0xaf, 0x0c, 0x5e, 0xb2, 0x90,
}

const messageToSign string = "mina-signer-go"

func TestDecodeSignatureGetAndString(t *testing.T) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i)
	}

	sig := signaturesdk.DecodeSignature(raw, mina.TestNet)
	require.Equal(t, raw, sig.Get())
	require.Equal(t, hex.EncodeToString(raw), sig.String())
}

func TestDecodeSignaturePreservesNetworkID(t *testing.T) {
	sig := signaturesdk.DecodeSignature(make([]byte, 64), mina.TestNet)
	require.Equal(t, mina.TestNet, sig.NetworkID)
}

func TestReferenceSignatureVerifies(t *testing.T) {
	_, public, sig := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := public.Verify(sig, messageToSign)
	require.NoError(t, err)
	require.True(t, validity)
}

func TestPublicKeyVerifyRejectsWrongMessage(t *testing.T) {
	_, public, sig := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := public.Verify(sig, messageToSign+"-wrong")
	require.False(t, validity)
	require.Error(t, err)
}

func TestPublicKeyVerifyRejectsMalformedSignature(t *testing.T) {
	_, public, _ := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := public.Verify(signaturesdk.DecodeSignature([]byte{0x01}, mina.MainNet), messageToSign)
	require.False(t, validity)
	require.Error(t, err)
}

func TestPublicKeyVerifyRejectsMismatchedNetwork(t *testing.T) {
	rawPublicKey, _, sig := referenceFixture(t, mina.MainNet, messageToSign)

	testnetPublicKey, err := publickey.DecodePublicKey(rawPublicKey, mina.TestNet)
	require.NoError(t, err)

	validity, err := testnetPublicKey.Verify(sig, messageToSign)
	require.False(t, validity)
	require.Error(t, err)
}

func referenceFixture(t *testing.T, networkID mina.NetworkID, message string) ([]byte, *publickey.PublicKey, *signature.Signature) {
	t.Helper()

	scalar, err := pasta.NewPallasScalarField().FromBytes(hardcodedPriv[:])
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

	pk, err := publickey.DecodePublicKey(rawPublicKey, networkID)
	require.NoError(t, err)

	return rawPublicKey, pk, signature.DecodeSignature(serialized, networkID)
}
