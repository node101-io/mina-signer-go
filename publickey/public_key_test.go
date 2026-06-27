package publickey_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/errors"
	minafield "github.com/node101-io/mina-signer-go/field"
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

var ValidEncodedSig string = "fe3f451da33c28f1561c43be4dd9df50518b8f9b2128f26712eae57de3c0211f26becbe775facc626b6bd8a5c5a0cb183fed214242111d52954079cdb9f33c14"

const messageToSign string = "mina-signer-go"

func TestPublicKey(t *testing.T) {

	privKey, err := privatekey.NewPrivateKeyFromBytes(validPrivateKeyBytes, mina.MainNet)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	sig, err := privKey.SignString(messageToSign)
	require.NoError(t, err)
	require.NotNil(t, sig)

	public, err := privKey.ToPublicKey()
	require.NoError(t, err)
	require.NotNil(t, public)

	validity, err := public.VerifyString(sig, messageToSign)
	require.NoError(t, err)
	require.True(t, validity)

}

func TestDecodePublicKeyRejectsInvalidBytes(t *testing.T) {
	pk, err := publickey.NewPublicKeyFromBytes([]byte{0x01, 0x02}, mina.MainNet)
	require.Nil(t, pk)
	require.Error(t, err)
}

func TestValidateAcceptsValidPublicKeyBytes(t *testing.T) {
	rawPublicKey, _, _ := referenceFixture(t, mina.MainNet, messageToSign)

	require.NoError(t, publickey.Validate(rawPublicKey))
}

func TestValidateRejectsShortPublicKeyBytes(t *testing.T) {
	err := publickey.Validate([]byte{0x01, 0x02})

	require.ErrorIs(t, err, errors.ErrInvalidPublicKeyLength)
}

func TestValidateAndDecodeRejectMalformedPublicKeyBytes(t *testing.T) {
	malformed := bytes.Repeat([]byte{0xff}, publickey.Size())

	require.Error(t, publickey.Validate(malformed))

	pk, err := publickey.NewPublicKeyFromBytes(malformed, mina.MainNet)
	require.Nil(t, pk)
	require.Error(t, err)
}

func TestSizeMatchesBronMina(t *testing.T) {
	require.Equal(t, mina.PublicKeySize, publickey.Size())
}

func TestDecodePublicKeyPreservesNetworkID(t *testing.T) {
	rawPublicKey, _, _ := referenceFixture(t, mina.TestNet, messageToSign)

	pk, err := publickey.NewPublicKeyFromBytes(rawPublicKey, mina.TestNet)
	require.NoError(t, err)
	require.Equal(t, mina.TestNet, pk.NetworkID())
}

func TestPublicKeyVerifyReturnsErrNilSignature(t *testing.T) {
	_, pk, _ := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := pk.VerifyString(nil, messageToSign)
	require.False(t, validity)
	require.ErrorIs(t, err, errors.ErrNilSignature)
}

func TestPublicKeyVerifyAcceptsValidSignature(t *testing.T) {
	_, pk, sig := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := pk.VerifyString(sig, messageToSign)
	require.NoError(t, err)
	require.True(t, validity)
}

func TestPublicKeyVerifyBytesAcceptsValidSignature(t *testing.T) {
	privKey, err := privatekey.NewPrivateKeyFromBytes(validPrivateKeyBytes, mina.MainNet)
	require.NoError(t, err)

	message := []byte(messageToSign)

	sig, err := privKey.SignBytes(message)
	require.NoError(t, err)
	require.NotNil(t, sig)

	pk, err := privKey.ToPublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)

	validity, err := pk.VerifyBytes(sig, message)
	require.NoError(t, err)
	require.True(t, validity)
}

func TestPublicKeyVerifyFieldElementAcceptsValidSignature(t *testing.T) {
	privKey, err := privatekey.NewPrivateKeyFromBytes(validPrivateKeyBytes, mina.MainNet)
	require.NoError(t, err)

	message := pasta.NewPallasBaseField().FromUint64(42)
	fieldElement, err := minafield.NewFieldElement(message.Bytes())
	require.NoError(t, err)
	require.NotNil(t, fieldElement)

	sig, err := privKey.SignFieldElement(fieldElement)
	require.NoError(t, err)
	require.NotNil(t, sig)

	pk, err := privKey.ToPublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)

	validity, err := pk.VerifyField(sig, fieldElement)
	require.NoError(t, err)
	require.True(t, validity)
}

func TestPublicKeyVerifyROIAcceptsValidSignature(t *testing.T) {
	privKey, err := privatekey.NewPrivateKeyFromBytes(validPrivateKeyBytes, mina.MainNet)
	require.NoError(t, err)

	message := new(mina.ROInput).Init()
	message.AddString(messageToSign)
	message.AddFields(pasta.NewPallasBaseField().FromUint64(42))
	message.AddBits(true, false, true)

	sig, err := privKey.SignROI(message)
	require.NoError(t, err)
	require.NotNil(t, sig)

	pk, err := privKey.ToPublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)

	validity, err := pk.VerifyROI(sig, message)
	require.NoError(t, err)
	require.True(t, validity)
}

func TestPublicKeyVerifyRejectsWrongMessage(t *testing.T) {
	_, pk, sig := referenceFixture(t, mina.MainNet, messageToSign)

	validity, err := pk.VerifyString(sig, "different-message")
	require.False(t, validity)
	require.Error(t, err)
}

func TestPublicKeyVerifyRejectsMalformedSignature(t *testing.T) {
	_, pk, _ := referenceFixture(t, mina.MainNet, messageToSign)

	decodedSig, err := hex.DecodeString(ValidEncodedSig)
	require.NoError(t, err)
	require.NotNil(t, decodedSig)

	decodedSig[len(decodedSig)-1] = byte(44)

	sig, err := localsignature.NewSignatureFromBytes(decodedSig)
	require.NotNil(t, sig)
	require.NoError(t, err)

	validity, err := pk.VerifyString(sig, messageToSign)
	require.False(t, validity)
	require.Error(t, err)
}

func TestPublicKeyVerifyRejectsMismatchedNetwork(t *testing.T) {
	rawPublicKey, _, sig := referenceFixture(t, mina.MainNet, messageToSign)

	testnetPublicKey, err := publickey.NewPublicKeyFromBytes(rawPublicKey, mina.TestNet)
	require.NoError(t, err)

	validity, err := testnetPublicKey.VerifyString(sig, messageToSign)
	require.False(t, validity)
	require.Error(t, err)
}

func TestPublicKeyToAddressReturnsErrNilPublicKey(t *testing.T) {
	var pk *publickey.PublicKey

	addr, err := pk.ToAddress()
	require.Nil(t, addr)
	require.ErrorIs(t, err, errors.ErrNilPublicKey)
}

func TestPublicKeyBytesReturnsNilForNilPublicKey(t *testing.T) {
	var pk *publickey.PublicKey

	require.Nil(t, pk.Bytes())
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

	newSig, err := localsignature.NewSignatureFromBytes(serialized)
	require.NotNil(t, newSig)
	require.NoError(t, err)

	return rawPublicKey, pk, newSig
}
