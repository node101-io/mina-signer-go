package signature

import (
	"encoding/hex"
)

type Signature struct {
	value []byte
}

func (sig *Signature) Get() []byte {
	return sig.value
}

// Hex Encoding
func (sig *Signature) String() string {
	return hex.EncodeToString(sig.value)
}

func DecodeSignature(sig []byte) *Signature {
	return &Signature{
		value: sig,
	}
}
