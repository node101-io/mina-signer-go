package publickey

import (
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/errors"
	"github.com/node101-io/mina-signer-go/signature"
)

type PublicKey struct {
	value                []byte
	networkID            mina.NetworkID
	bronCompatiblePublic *mina.PublicKey
}

func (pk *PublicKey) NetworkID() mina.NetworkID {
	return pk.networkID
}

func (pk *PublicKey) Verify(signature *signature.Signature, message string) (bool, error) {

	if signature == nil {
		return false, errors.ErrNilSignature
	}

	if pk == nil {
		return false, errors.ErrNilSignature
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

// input public key string is expected to be hex encoded
func DecodePubKeyFromString(publicKey string, networkID mina.NetworkID) (*PublicKey, error) {

	pk, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	return NewPublicKeyFromBytes(pk, networkID)
}

func cloneBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}

func (pk *PublicKey) Bytes() ([]byte, error) {
	if pk == nil {
		return nil, errors.ErrNilPublicKey
	}
	return cloneBytes(pk.value), nil
}

func NewPublicKeyFromBytes(pk []byte, networkID mina.NetworkID) (*PublicKey, error) {
	if len(pk) != mina.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d want %d", len(pk), mina.PublicKeySize)
	}

	point, err := pasta.NewPallasCurve().FromBytes(pk)
	if err != nil {
		return nil, err
	}

	publicBron, err := mina.NewPublicKey(point)
	if err != nil {
		return nil, err
	}

	raw := publicBron.Value().Bytes()

	return &PublicKey{
		value:                cloneBytes(raw),
		networkID:            networkID,
		bronCompatiblePublic: publicBron,
	}, nil
}
