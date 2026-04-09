package minasignergo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/bronlabs/errs-go/errs"
)

type PrivateKey struct {
	Value     []byte
	NetworkID mina.NetworkID
}

type Signature struct {
	Value     []byte
	NetworkID mina.NetworkID
}

type PublicKey struct {
	Value     []byte
	NetworkID mina.NetworkID
}

func (sig *Signature) String() string {
	return string(sig.Value)
}

func NewPrivateKeyFromBytes(data [32]byte, networkID mina.NetworkID) (*PrivateKey, error) {
	privKey, err := decodePrivateKeyBytes(data[:])
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		Value:     privKey.Value().Bytes(),
		NetworkID: networkID,
	}, nil
}

func (privKey *PrivateKey) Sign(message string, networkId mina.NetworkID) (*Signature, error) {
	if privKey == nil {
		return nil, errs.New("private key is nil")
	}

	bronCompatiblePriv, err := decodePrivateKeyBytes(privKey.Value)
	if err != nil {
		return nil, err
	}
	scheme, err := mina.NewScheme(networkId, bronCompatiblePriv)
	if err != nil {
		return nil, err
	}

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	signer, err := scheme.Signer(bronCompatiblePriv)
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

	return &Signature{
		Value:     serialized,
		NetworkID: networkId,
	}, nil
}

func (privKey *PrivateKey) SigVerify(signature *Signature, message string, networkID mina.NetworkID) (bool, error) {
	if privKey == nil {
		return false, errs.New("private key is nil")
	}
	if signature == nil {
		return false, errs.New("signature is nil")
	}

	bronCompatiblePriv, err := decodePrivateKeyBytes(privKey.Value)
	if err != nil {
		return false, err
	}

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	sig, err := mina.DeserializeSignature(signature.Value)
	if err != nil {
		return false, err
	}

	scheme, err := mina.NewScheme(networkID, bronCompatiblePriv)
	if err != nil {
		return false, err
	}

	verifier, err := scheme.Verifier()
	if err != nil {
		return false, err
	}
	if err := verifier.Verify(sig, bronCompatiblePriv.PublicKey(), msg); err != nil {
		return false, err
	}

	return true, nil
}

func (privKey *PrivateKey) ToPublicKey() (*PublicKey, error) {
	bronCompatiblePriv, err := decodePrivateKeyBytes(privKey.Value)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		Value:     bronCompatiblePriv.PublicKey().Value().Bytes(),
		NetworkID: privKey.NetworkID,
	}, nil
}

func decodePrivateKeyBytes(data []byte) (*mina.PrivateKey, error) {

	scalar, err := pasta.NewPallasScalarField().FromBytes(data)
	if err != nil {
		return nil, err
	}

	return mina.NewPrivateKey(scalar)
}
