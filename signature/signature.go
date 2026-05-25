package signature

import (
	"bytes"
	"encoding/hex"

	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/errors"
)

type Signature struct {
	value []byte
}

// Size returns the size in bytes of a serialized Mina signature.
func Size() int {
	return mina.SignatureSize
}

// Hex Encoding
func (sig *Signature) String() string {
	return hex.EncodeToString(sig.value)
}

func (sig *Signature) Bytes() []byte {
	if sig == nil {
		return nil
	}
	return bytes.Clone(sig.value)
}

func NewSignatureFromBytes(sig []byte) (*Signature, error) {
	if len(sig) != Size() {
		return nil, errors.ErrInvalidSignatureLength
	}

	if _, err := mina.DeserializeSignature(sig); err != nil {
		return nil, err
	}

	return &Signature{
		value: bytes.Clone(sig),
	}, nil
}

// input sig string is expected to be hex encoded
func DecodeSignatureFromString(sig string) (*Signature, error) {

	b, err := hex.DecodeString(sig)
	if err != nil {
		return nil, err
	}
	return NewSignatureFromBytes(b)
}
