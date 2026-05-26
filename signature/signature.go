package signature

import (
	"bytes"
	"fmt"
	"strings"

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

// Debugging purposes only
func (sig *Signature) String() string {
	return strings.Clone(fmt.Sprint(sig.value))
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
