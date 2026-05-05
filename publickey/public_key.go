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
var ErrNilPublicKey = errors.New("nil public key")

type PublicKey struct {
	value                []byte
	networkID            mina.NetworkID
	bronCompatiblePublic *mina.PublicKey
}

func (pk *PublicKey) Bytes() ([]byte, error) {
	if pk == nil {
		return nil, ErrNilPublicKey
	}
	return pk.value, nil
}

func (pk *PublicKey) NetworkID() mina.NetworkID {
	return pk.networkID
}

func (pk *PublicKey) Verify(signature *signature.Signature, message string) (bool, error) {

	if signature == nil {
		return false, ErrNilSignature
	}

	if pk == nil {
		return false, ErrNilSignature
	}

	sig, err := mina.DeserializeSignature(signature.Bytes())
	if err != nil {
		return false, err
	}

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	scheme, err := mina.NewRandomisedScheme(pk.networkID, pcg.NewRandomised())
	if err != nil {
		return false, err
	}

	verifier, err := scheme.Verifier()
	if err != nil {
		return false, err
	}

	err = verifier.Verify(sig, pk.bronCompatiblePublic, msg)
	if err != nil {
		return false, err
	}

	return true, nil
}

// Hex Encoding
func (pk *PublicKey) String() string {
	return hex.EncodeToString(pk.value)
}

func NewPublicKeyFromBytes(pk []byte, networkID mina.NetworkID) (*PublicKey, error) {

	point, err := pasta.NewPallasCurve().FromBytes(pk)
	if err != nil {
		return nil, err
	}

	publicBron, err := mina.NewPublicKey(point)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		value:                publicBron.Value().Bytes(),
		networkID:            networkID,
		bronCompatiblePublic: publicBron,
	}, nil
}
