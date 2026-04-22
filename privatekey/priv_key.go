package privatekey

import (
	"errors"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/publickey"
	"github.com/node101-io/mina-signer-go/signature"
)

var ErrNilPrivateKey = errors.New("nil private key")
var ErrInternal = errors.New("internal error")

type PrivateKey struct {
	value              []byte
	bronCompatiblePriv *mina.PrivateKey
	networkID          mina.NetworkID
}

func (priv *PrivateKey) GetNetworkID() mina.NetworkID {
	return priv.networkID
}

func NewPrivateKeyFromBytes(data [32]byte, networkID mina.NetworkID) (*PrivateKey, error) {
	privKey, err := decodePrivateKeyBytes(data[:])
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		value:              privKey.Value().Bytes(),
		bronCompatiblePriv: privKey,
		networkID:          networkID,
	}, nil
}

func (privKey *PrivateKey) Sign(message string) (*signature.Signature, error) {

	if privKey == nil {
		return nil, ErrNilPrivateKey
	}

	scheme, err := mina.NewScheme(privKey.networkID, privKey.bronCompatiblePriv)
	if err != nil {
		return nil, err
	}

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	signer, err := scheme.Signer(privKey.bronCompatiblePriv)
	if err != nil {
		return nil, err
	}

	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, err
	}

	serialized, err := mina.SerializeSignature(sig)
	if err != nil {
		return nil, err
	}

	return signature.DecodeSignature(serialized), nil

}

func (privKey *PrivateKey) ToPublicKey() (*publickey.PublicKey, error) {
	pk, err := publickey.DecodePublicKey(privKey.bronCompatiblePriv.PublicKey().Value().Bytes(), privKey.networkID)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, ErrInternal
	}
	return pk, err
}

func decodePrivateKeyBytes(data []byte) (*mina.PrivateKey, error) {

	scalar, err := pasta.NewPallasScalarField().FromBytes(data)
	if err != nil {
		return nil, err
	}

	return mina.NewPrivateKey(scalar)
}
