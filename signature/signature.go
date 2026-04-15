package signature

import (
	"encoding/hex"

	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

type Signature struct {
	value     []byte
	NetworkID mina.NetworkID
}

func (sig *Signature) Get() []byte {
	return sig.value
}

func (sig *Signature) String() string {
	return hex.EncodeToString(sig.value)
}

func DecodeSignature(sig []byte, networkID mina.NetworkID) *Signature {
	return &Signature{
		value:     sig,
		NetworkID: networkID,
	}
}
