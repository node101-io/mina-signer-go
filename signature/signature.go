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

func NewSignatureFromBytes(sig []byte) *Signature {
	return &Signature{
		value: sig,
	}
}
