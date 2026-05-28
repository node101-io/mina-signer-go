package publickey

import (
	"bytes"
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/address"
	"github.com/node101-io/mina-signer-go/errors"
	"github.com/node101-io/mina-signer-go/signature"
)

type PublicKey struct {
	networkID            mina.NetworkID
	bronCompatiblePublic *mina.PublicKey
}

// Size returns the size in bytes of a serialized Mina public key.
func Size() int {
	return mina.PublicKeySize
}

// Validate checks whether pk is a well-formed serialized Mina public key.
func Validate(pk []byte) error {
	_, err := parsePublicKey(pk)
	return err
}

func (pk *PublicKey) NetworkID() mina.NetworkID {
	return mina.NetworkID(strings.Clone(string(pk.networkID)))
}

func (pk *PublicKey) VerifyString(signature *signature.Signature, message string) (bool, error) {

	if pk == nil {
		return false, errors.ErrNilPublicKey
	}

	if signature == nil {
		return false, errors.ErrNilSignature
	}

	if message == "" {
		return false, errors.ErrNilMessage
	}

	msg := new(mina.ROInput).Init()
	msg.AddString(message)

	return pk.VerifyROI(signature, msg)
}

func (pk *PublicKey) VerifyFieldElement(signature *signature.Signature, message *pasta.PallasBaseFieldElement) (bool, error) {

	if pk == nil {
		return false, errors.ErrNilPublicKey
	}

	if signature == nil {
		return false, errors.ErrNilSignature
	}

	if message == nil {
		return false, errors.ErrNilMessage
	}

	msg := new(mina.ROInput).Init()
	msg.AddFields(message)

	return pk.VerifyROI(signature, msg)
}

func (pk *PublicKey) VerifyBytes(signature *signature.Signature, message []byte) (bool, error) {

	if pk == nil {
		return false, errors.ErrNilPublicKey
	}

	if message == nil {
		return false, errors.ErrNilMessage
	}

	msg := new(mina.ROInput).Init()

	for _, msgByte := range message {
		for i := 0; i < 8; i++ {
			bit := (msgByte>>(7-i))&1 == 1
			msg.AddBits(bit)
		}
	}

	return pk.VerifyROI(signature, msg)
}

func (pk *PublicKey) VerifyROI(signature *signature.Signature, msg *mina.ROInput) (bool, error) {

	if signature == nil {
		return false, errors.ErrNilSignature
	}

	if pk == nil {
		return false, errors.ErrNilPublicKey
	}

	sig, err := mina.DeserializeSignature(signature.Bytes())
	if err != nil {
		return false, err
	}

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

// Debugging purposes only
func (pk *PublicKey) String() string {
	return strings.Clone(pk.bronCompatiblePublic.String())
}

func (pk *PublicKey) Bytes() []byte {
	if pk == nil {
		return nil
	}

	return bytes.Clone(pk.bronCompatiblePublic.Value().Bytes())
}

func parsePublicKey(pk []byte) (*mina.PublicKey, error) {
	if len(pk) != Size() {
		return nil, errors.ErrInvalidPublicKeyLength
	}

	point, err := pasta.NewPallasCurve().FromBytes(pk)
	if err != nil {
		return nil, err
	}

	publicBron, err := mina.NewPublicKey(point)
	if err != nil {
		return nil, err
	}

	return publicBron, nil
}

func NewPublicKeyFromBytes(pk []byte, networkID mina.NetworkID) (*PublicKey, error) {
	publicBron, err := parsePublicKey(pk)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		networkID:            networkID,
		bronCompatiblePublic: publicBron,
	}, nil
}

func (pk *PublicKey) ToAddress() (*address.Address, error) {
	if pk == nil {
		return nil, errors.ErrNilPublicKey
	}

	encoded, err := mina.EncodePublicKey(pk.bronCompatiblePublic)
	if err != nil {
		return nil, err
	}

	return address.NewAddress(string(encoded)), nil
}
