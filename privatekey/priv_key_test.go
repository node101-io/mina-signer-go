package privatekey

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/errors"
	"github.com/stretchr/testify/require"
)

var hardcodedPriv = [32]byte{
	0x3a, 0x7f, 0x1c, 0x92, 0xe4, 0x55, 0x8b, 0xd1,
	0x6f, 0x20, 0xa9, 0x3c, 0x77, 0x4e, 0x11, 0x5d,
	0x88, 0xca, 0x02, 0xf6, 0x9b, 0x31, 0x44, 0x7a,
	0xde, 0x63, 0x19, 0xaf, 0x0c, 0x5e, 0xb2, 0x90,
}

const hardcodedMsg string = "mina-signer-go"

func TestSignNilPrivateKeyReturnsErrNilPrivateKey(t *testing.T) {
	var privKey *PrivateKey

	sig, err := privKey.SignString(hardcodedMsg)
	require.Nil(t, sig)
	require.ErrorIs(t, err, errors.ErrNilPrivateKey)
}

func TestDecodePrivateKeyBytesRejectsInvalidLength(t *testing.T) {
	privKey, err := decodePrivateKeyBytes([]byte{0x01, 0x02})
	require.Nil(t, privKey)
	require.Error(t, err)
}

func TestDecodePrivateKeyBytesAcceptsValidBytes(t *testing.T) {
	privKey, err := decodePrivateKeyBytes(hardcodedPriv[:])
	require.NoError(t, err)
	require.NotNil(t, privKey)
	require.Len(t, privKey.Value().Bytes(), len(hardcodedPriv))
}

func TestSignProducesVerifiableSignatureWhenBronCompatiblePrivateKeyIsPresent(t *testing.T) {
	privKey := mustPrivateKeyWithBron(t, mina.MainNet)

	sig, err := privKey.SignString(hardcodedMsg)
	require.NoError(t, err)
	require.NotNil(t, sig)

	public, err := privKey.ToPublicKey()
	require.NoError(t, err)
	require.NotNil(t, public)

	validity, err := public.VerifyString(sig, hardcodedMsg)
	require.NoError(t, err)
	require.True(t, validity)
}

func TestToPublicKeyMatchesBronPublicKeyWhenBronCompatiblePrivateKeyIsPresent(t *testing.T) {
	bronPriv := initBronPrivKey(t)
	privKey := &PrivateKey{
		bronCompatiblePriv: bronPriv,
		networkID:          mina.MainNet,
	}

	public, err := privKey.ToPublicKey()
	require.NoError(t, err)

	pkValue, err := public.Bytes()
	require.NoError(t, err)

	require.Equal(t, bronPriv.PublicKey().Value().Bytes(), pkValue)
}

func mustPrivateKeyWithBron(t *testing.T, networkID mina.NetworkID) *PrivateKey {
	t.Helper()

	bronPriv := initBronPrivKey(t)
	return &PrivateKey{
		bronCompatiblePriv: bronPriv,
		networkID:          networkID,
	}
}

func initBronPrivKey(t *testing.T) *mina.PrivateKey {
	t.Helper()

	scalar, err := pasta.NewPallasScalarField().FromBytes(hardcodedPriv[:])
	require.NoError(t, err)

	privKey, err := mina.NewPrivateKey(scalar)
	require.NoError(t, err)

	return privKey
}
