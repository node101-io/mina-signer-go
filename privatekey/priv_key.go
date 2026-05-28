package privatekey

import (
	"bytes"
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/errors"
	"github.com/node101-io/mina-signer-go/publickey"
	"github.com/node101-io/mina-signer-go/signature"
)

type PrivateKey struct {
	bronCompatiblePriv *mina.PrivateKey
	networkID          mina.NetworkID
}

// Size returns the size in bytes of a serialized Mina private key.
func Size() int {
	return mina.PrivateKeySize
}

// Validate checks whether data is a well-formed serialized Mina private key.
func Validate(data []byte) error {
	_, err := parsePrivateKey(data)
	return err
}

func (priv *PrivateKey) GetNetworkID() mina.NetworkID {
	return mina.NetworkID(strings.Clone(string(priv.networkID)))
}

func (privKey *PrivateKey) Bytes() []byte {
	if privKey == nil {
		return nil
	}

	return bytes.Clone(privKey.bronCompatiblePriv.Value().Bytes())
}

func parsePrivateKey(data []byte) (*mina.PrivateKey, error) {
	if len(data) != Size() {
		return nil, errors.ErrInvalidPrivateKeyLength
	}

	scalar, err := pasta.NewPallasScalarField().FromBytes(data)
	if err != nil {
		return nil, err
	}

	privKey, err := mina.NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func NewPrivateKeyFromBytes(data [32]byte, networkID mina.NetworkID) (*PrivateKey, error) {
	privKey, err := parsePrivateKey(data[:])
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		bronCompatiblePriv: privKey,
		networkID:          networkID,
	}, nil
}

func (privKey *PrivateKey) SignString(msg string) (*signature.Signature, error) {

	if privKey == nil {
		return nil, errors.ErrNilPrivateKey
	}

	if msg == "" {
		return nil, errors.ErrNilMessage
	}

	message := new(mina.ROInput).Init()
	message.AddString(msg)

	return privKey.SignROI(message)
}

func (privKey *PrivateKey) SignBytes(msg []byte) (*signature.Signature, error) {

	if privKey == nil {
		return nil, errors.ErrNilPrivateKey
	}

	if msg == nil {
		return nil, errors.ErrNilMessage
	}

	message := new(mina.ROInput).Init()

	for _, msgByte := range msg {

		for i := 0; i < 8; i++ {

			bit := (msgByte>>(7-i))&1 == 1
			message.AddBits(bit)

		}

	}

	return privKey.SignROI(message)
}

func (privKey *PrivateKey) SignFieldElement(msg *pasta.PallasBaseFieldElement) (*signature.Signature, error) {

	if privKey == nil {
		return nil, errors.ErrNilPrivateKey
	}

	if msg == nil {
		return nil, errors.ErrNilMessage
	}

	message := new(mina.ROInput).Init()

	message.AddFields(msg)

	return privKey.SignROI(message)
}

func (privKey *PrivateKey) SignROI(msg *mina.ROInput) (*signature.Signature, error) {

	if privKey == nil {
		return nil, errors.ErrNilPrivateKey
	}

	if msg == nil {
		return nil, errors.ErrNilMessage
	}

	scheme, err := mina.NewScheme(privKey.networkID, privKey.bronCompatiblePriv)
	if err != nil {
		return nil, err
	}

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

	return signature.NewSignatureFromBytes(serialized)

}

func (privKey *PrivateKey) ToPublicKey() (*publickey.PublicKey, error) {

	if privKey == nil {
		return nil, errors.ErrNilPrivateKey
	}

	pk, err := publickey.NewPublicKeyFromBytes(privKey.bronCompatiblePriv.PublicKey().Value().Bytes(), privKey.networkID)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.ErrInternal
	}
	return pk, err
}
