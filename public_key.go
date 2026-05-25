package minasignergo

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

func (pk *PublicKey) SigVerify(signature *Signature, message string) (bool, error) {

	sig, err := mina.DeserializeSignature(signature.Value)
	if err != nil {
		return false, err
	}

	publicKeyBronCompatible, err := pk.ToBron()
	if err != nil {
		return false, err
	}

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	scheme, err := mina.NewRandomisedScheme(mina.MainNet, pcg.NewRandomised())
	if err != nil {
		return false, err
	}

	verifier, err := scheme.Verifier()
	if err != nil {
		return false, err
	}

	err = verifier.Verify(sig, publicKeyBronCompatible, msg)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (pk *PublicKey) ToBron() (*mina.PublicKey, error) {
	point, err := pasta.NewPallasCurve().FromBytes(pk.Value)
	if err != nil {
		return nil, err
	}
	return mina.NewPublicKey(point)
}

func (pk *PublicKey) String() string {
	return string(pk.Value)
}

func DecodePublicKey(pk []byte, networkID mina.NetworkID) (*PublicKey, error) {
	point, err := pasta.NewPallasCurve().FromBytes(pk)
	if err != nil {
		return nil, err
	}

	publicBron, err := mina.NewPublicKey(point)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		Value:     publicBron.Value().Bytes(),
		NetworkID: networkID,
	}, nil
}
