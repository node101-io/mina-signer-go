package signature

import (
	"encoding/hex"
)

type Signature struct {
	value []byte
}

func (sig *Signature) Bytes() []byte {
	return sig.value
}

// Hex Encoding
func (sig *Signature) String() string {
	return hex.EncodeToString(sig.value)
}

// input sig string is expected to be hex encoded
func DecodeSignatureFromString(sig string) (*Signature, error) {

	sigValue, err := hex.DecodeString(sig)
	if err != nil {
		return nil, err
	}

	return &Signature{
		value: sigValue,
	}, nil
}

func NewSignatureFromBytes(sig []byte) *Signature {
	return &Signature{
		value: sig,
	}
}
