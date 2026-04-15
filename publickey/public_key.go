package publickey

import (
	"encoding/hex"
	"errors"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/signature"
)

var ErrNilSignature = errors.New("nil signature")

type PublicKey struct {
	value     []byte
	NetworkID mina.NetworkID
}

func (pk *PublicKey) Get() []byte {
	return pk.value
}

func (pk *PublicKey) Verify(signature *signature.Signature, message string) (bool, error) {

	if signature == nil {
		return false, ErrNilSignature
	}

	sig, err := mina.DeserializeSignature(signature.Get())
	if err != nil {
		return false, err
	}

	publicKeyBronCompatible, err := pk.toBron()
	if err != nil {
		return false, err
	}

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	scheme, err := mina.NewRandomisedScheme(pk.NetworkID, pcg.NewRandomised())
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

func (pk *PublicKey) toBron() (*mina.PublicKey, error) {
	point, err := pasta.NewPallasCurve().FromBytes(pk.value)
	if err != nil {
		return nil, err
	}
	return mina.NewPublicKey(point)
}

func (pk *PublicKey) String() string {
	return hex.EncodeToString(pk.value)
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
		value:     publicBron.Value().Bytes(),
		NetworkID: networkID,
	}, nil
}
